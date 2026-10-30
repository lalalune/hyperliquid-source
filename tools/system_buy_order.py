#!/usr/bin/env python3
"""Pin the node #94 `0xfe` user spot buy cycle and its block step, from ELF bytes.

`0x26fed00` runs once per block and on one action: it moves the `0xfe` user's perp balance above a
floor to spot, runs `hyperliquidity_ensure_orders` when a time bucket rolls over, then calls
`0x1e83350`. That function walks a config tree, cancels the user's orders in one spot book, feeds the
top of the book into a two-field decaying average, and when five gates pass places one new order.
The real bytes of both functions and of the top-of-book reader `0x23978c0` run in a Python evaluator
with only the edges stubbed, a separately written specification predicts every edge call and every
state byte, and every condition, immediate and field offset is then flipped to show the run can
tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library
only.
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

DRIVER = 0x26FED00
CYCLE = 0x1E83350
BEST = 0x23978C0
CANCEL = 0x26E4240
PLACE = 0x26CC730
TICK = 0x230B590
MAP_NEXT = 0x286ADA0
DROP_ERROR = 0x1EAD7F0
TRANSFER = 0x270F6F0
TRANSFER_DROP = 0x277EBA0
ENSURE = 0x26CB280
SPAN = 0x22293C0
FLUSH = 0x24FC8A0
CALLERS = ((0x222A0F5, 0x22297C0, 0), (0x23E85E8, 0x23E7D10, 1))

SLOT_ELAPSED = 0x576E8C0
SLOT_CONVERT = 0x57731F0
SLOT_LOOKUP = 0x5773170
SLOT_FREE = 0x576E010
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAILED = 0x576DFB8
SLOT_BALANCE = 0x5774660
SLOT_PANIC = 0x576E470
SLOT_BOUNDS = 0x576DFC8
SLOT_OVERFLOW = 0x576E150
SLOT_NAMES = {SLOT_ELAPSED: "elapsed seconds", SLOT_CONVERT: "f64 price to raw price", SLOT_LOOKUP: "user map lookup",
              SLOT_BALANCE: "movable amount of a user in one market, stubbed", SLOT_PANIC: "panic with Location", SLOT_BOUNDS: "index bounds panic",
              SLOT_OVERFLOW: "subtract overflow panic"}

LOCATION_BOOKS = 0x56BB478
LOCATION_NAVIGATE = 0x56905C8
LOCATION_PAIR = 0x5690308
LOCATION_TOKEN = 0x56F21F0
LOCATION_DECIMALS = 0x56F2258
LOCATION_PAIR_AGAIN = 0x56F1FD8
LOCATIONS = (LOCATION_BOOKS, LOCATION_NAVIGATE, LOCATION_PAIR, LOCATION_TOKEN, LOCATION_DECIMALS, LOCATION_PAIR_AGAIN)

TIME_PATH = 0x5B9765
TIME_PATH_SIZE = 0x2B
TIME_LINE = 0x54
USER_WORD = 0x206BE0
F64_ONE = 0x20A730
F64_TEN = 0x20A8A8
F64_FLOOR = 0x20B080
F64_NEG_FLOOR = 0x20A448
POW10 = 0x3E0E90
SPAN_NAME = 0x3EF968
SPAN_NAME_TEXT = b"hyperliquidity_ensure_orders"
SPAN_OPTIONS = 0x2055A0

OK_STATUS = 0x186
TRANSFER_FLOOR = 1000000000
FILL_STRIDE = 0x228
BOOK_STRIDE = 0xD8
PAIR_STRIDE = 0x20
TOKEN_STRIDE = 0xE8
MARKET_STRIDE = 0x2F0
ENTRY_SIZE = 0x48
NICHE = 1 << 63

FIELD_TIME = 0x60
FIELD_USER_MAP = 0x80
FIELD_SPOT_META = 0x90
FIELD_PAIRS = 0x1F8
FIELD_TOKENS = 0x210
FIELD_MARKETS = 0x5C0
FIELD_NETWORK = 0x8F2
FIELD_SPOT_BOOKS = 0x3380
FIELD_PERIOD = 0x38D0
FIELD_LAST = 0x38D8
FIELD_TREE = 0x3A00
FIELD_GATE = 0x3AC8

# B-tree node shapes: the config tree, the balance tree and the side tree of a book.
ENTRY_NODE = dict(parent=0, keys=8, values=0x60, index=0x378, length=0x37A, edges=0x380, size=0x3E0)
BALANCE_NODE = dict(keys=8, values=0x60, stride=0x18, length=0x16A, edges=0x170, size=0x1D0)
SIDE_NODE = dict(parent=0x160, keys=0x168, index=0x1C0, length=0x1C2, edges=0x1C8, size=0x228)

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
MUTANT_STEP_LIMIT = 30000
UNMAPPED = 0x7300000000

EX = HEAP_BASE + 0x1000
BOOKS = EX + 0x4000
EVENTS = EX + 0x3F00
MARKETS = BOOKS + 16 * BOOK_STRIDE
PAIRS = MARKETS + 4 * MARKET_STRIDE
TOKENS = PAIRS + 16 * PAIR_STRIDE
BUMP = TOKENS + 8 * TOKEN_STRIDE
FE_USER = b"\xfe" * 20
FF_USER = b"\xff" * 20
# The driver's frame: entry rsp, six pushes, then `sub rsp, 0x108`.
DRIVER_FRAME = STACK_TOP - 0x108 - 0x30 - 0x108
DRIVER_EVENTS = DRIVER_FRAME + 0x20

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
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm(True)
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
        vector = {(0x57, False): "xorps", (0x57, True): "xorps", (0xEF, True): "xorps", (0x15, True): "unpckhpd", (0x5C, True): "subpd",
                  (0x54, True): "andpd", (0x56, True): "orpd", (0x62, True): "punpckldq", (0x14, False): "punpckldq",
                  (0x55, True): "andnpd", (0x14, True): "unpcklpd", (0x58, True): "addpd", (0x59, True): "mulpd", (0x76, True): "pcmpeqd"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x59, 0x5C, 0x5D, 0x5E, 0x5F) and repne:
            reg, rm = modrm(True)
            return finish({0x58: "addsd", 0x59: "mulsd", 0x5C: "subsd", 0x5D: "minsd", 0x5E: "divsd", 0x5F: "maxsd"}[two], ("x", reg), rm, 8)
        if two == 0xC2 and repne:
            reg, rm = modrm(True)
            value = immediate(1)
            if value not in (0, 1, 3):
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish({0: "cmpeqsd", 1: "cmpltsd", 3: "cmpunordsd"}[value], ("x", reg), rm, 8)
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
        elif op in ("cmpeqsd", "cmpltsd", "cmpunordsd"):
            left, right = to_float(self.low(row.a)), to_float(self.low(row.b))
            truth = left == right if op == "cmpeqsd" else left < right if op == "cmpltsd" else (left != left or right != right)
            self.set_low(row.a[1], MASK[8] if truth else 0)
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
        elif op in ("addpd", "mulpd"):
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            pair = (to_float(left & MASK[8]), to_float(right & MASK[8])), (to_float(left >> 64), to_float(right >> 64))
            low, high = [(a + b if op == "addpd" else a * b) for a, b in pair]
            self.xmm[row.a[1]] = to_bits(low) | to_bits(high) << 64
        elif op == "unpcklpd":
            self.xmm[row.a[1]] = (self.xmm[row.a[1]] & MASK[8]) | (self.vector(row.b) & MASK[8]) << 64
        elif op == "pcmpeqd":
            right = self.vector(row.b)
            left = self.xmm[row.a[1]]
            self.xmm[row.a[1]] = sum((MASK[4] if (left >> at) & MASK[4] == (right >> at) & MASK[4] else 0) << at for at in (0, 32, 64, 96))
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



# ---- specification, written from the reading and never from a run ----

def days_from_epoch(year, ordinal):
    """Days from 1970-01-01 to an ordinal date, proleptic Gregorian, any sign of year."""
    shift = 0
    while year <= 0:
        year += 400
        shift -= 146097
    previous = year - 1
    return previous * 365 + previous // 4 - previous // 100 + previous // 400 + ordinal - 1 - 719162 + shift


def pack_date(year, ordinal, flags=0xA):
    return ((year << 13) | (ordinal << 4) | flags) & MASK[4]


def time_millis(moment):
    """The time word as whole non-negative milliseconds."""
    word, seconds, nanos = moment
    signed = word - (1 << 32) if word & SIGN[4] else word
    days = days_from_epoch(signed >> 13, (word >> 4) & 0x1FF)
    total = (days * 86400 + seconds) * 1000 + nanos // 1000000
    return total if total > 0 else 0


class Entry:
    FIELDS = ("key", "total", "weight", "window", "count", "word", "seconds", "nanos", "index", "amount", "cap")

    def __init__(self, index=0, total=0.0, weight=0.0, window=30.0, count=100, word=0, seconds=0, nanos=0, amount=1000000, cap=1e9, key=None):
        self.index, self.total, self.weight, self.window, self.count = index, total, weight, window, count
        self.word, self.seconds, self.nanos, self.amount, self.cap = word, seconds, nanos, amount, cap
        self.key = index if key is None else key

    def copy(self):
        twin = Entry()
        for name in self.FIELDS:
            setattr(twin, name, getattr(self, name))
        return twin

    def pack(self):
        return struct.pack("<dddQIIIIQQd", self.total, self.weight, self.window, self.count, self.word, self.seconds, self.nanos,
                           0xA5A5A5A5, self.index, self.amount, self.cap)


DEFAULT_TOKENS = ((3, 8), (0, 6), (8, 8), (2, 18))
DEFAULT_PAIRS = ((0, 1), (2, 1), (1, 2), (0, 0), (2, 0), (3, 3), (1, 3), (0, 3))
NOW = (pack_date(2026, 303), 45296, 789000000)
EARLIER = (pack_date(2026, 303), 45290, 111000000)


class CycleCase:
    def __init__(self, label, entries, shape="flat", claimed=None, books=None, pairs=DEFAULT_PAIRS, tokens=DEFAULT_TOKENS, now=NOW, balances=(), balance_depth=0,
                 elapsed=None, prices=None, ticks=None, places=None, header=True, book_count=None):
        self.label, self.entries, self.shape = label, entries, shape
        self.claimed = len(entries) if claimed is None else claimed
        self.books = books if books is not None else {}
        self.pairs, self.tokens, self.now = pairs, tokens, now
        self.balances, self.balance_depth = balances, balance_depth
        self.elapsed = elapsed or {}
        self.prices = prices or {}
        self.ticks = ticks or {}
        self.places = places or {}
        self.header = header
        self.book_count = 8 if book_count is None else book_count


DEFAULT_BOOK = (-2500000, 2510000, 0)
DEFAULT_BALANCES = ((1, 1 << 40), (0, 1 << 40), (2, 1 << 40), (3, 1 << 40))


def f64_below(value):
    return to_float(to_bits(value) - 1 if value > 0 else to_bits(value) + 1)


def f64_above(value):
    return to_float(to_bits(value) + 1 if value > 0 else to_bits(value) - 1)


def spec_divide(left, right):
    if right == 0.0:
        if left != left or left == 0.0:
            return math.nan
        return math.copysign(math.inf, left) * math.copysign(1.0, right)
    return left / right


def book_top(shape):
    """The first key of the book's +0x80 tree as a magnitude, 0 for no key."""
    if shape is None or shape[0] is None:
        return 0
    if shape[0] == "empty":
        return 0
    key = shape[0]
    return ((-key) & MASK[8]) if key < 0 else key


def error_body(status):
    return bytes([status & 0xFF, status >> 8]) + bytes((0x30 + value) & 0xFF for value in range(2, 0x60))


def spec_cycle(case):
    """Predict the edge calls, the final entries and the stop of one run of the cycle."""
    if not case.header:
        return {"events": [], "entries": [row.pack() for row in case.entries], "stop": None}
    events = []
    entries = [row.copy() for row in case.entries]
    balances = dict(case.balances)
    finish = lambda stop=None: {"events": events, "entries": [row.pack() for row in entries], "stop": stop}
    if case.claimed == 0:
        return finish()
    for position in range(case.claimed):
        if position >= len(entries):
            return finish(("panic", LOCATION_NAVIGATE))
        entry = entries[position]
        index = entry.index
        if index >= case.book_count:
            return finish(("panic", LOCATION_BOOKS))
        book = BOOKS + index * BOOK_STRIDE
        events.append(("cancel", book, FE_USER.hex(), 1, EX, EVENTS, 2))
        best = book_top(case.books.get(index, DEFAULT_BOOK))
        if best == 0:
            continue
        if index >= len(case.pairs):
            return finish(("bounds", index, len(case.pairs), LOCATION_PAIR_AGAIN))
        base, quote = case.pairs[index]
        if quote >= len(case.tokens) or base >= len(case.tokens):
            return finish(("panic", LOCATION_TOKEN))
        scale = case.tokens[quote][1] - case.tokens[base][0]
        if scale < 0:
            return finish(("overflow", LOCATION_DECIMALS))
        sample = float(best) / (10.0 ** scale)
        seconds = 1.0
        if entry.word != 0:
            seconds = case.elapsed.get(position, 1.0)
            events.append(("elapsed", case.now, (entry.word, entry.seconds, entry.nanos), 1, TIME_LINE, TIME_PATH, TIME_PATH_SIZE))
        window = entry.window
        if seconds > window:
            entry.total = entry.weight = 0.0
            entry.window = max(10.0, window)
            entry.count = 0
            entry.word = 0
        else:
            entry.word, entry.seconds, entry.nanos = case.now
            decay = 1.0 - spec_divide(1.0, window)
            entry.total = sample * seconds + decay * entry.total
            entry.weight = seconds + decay * entry.weight
            entry.count = min(entry.count + 1, MASK[8])
        if entry.window > float(entry.count):
            continue
        if 1e-15 > entry.weight:
            continue
        total = entry.total
        if total < 0.0:
            total = 0.0 if -1e-15 < total else total
        if 0.0 > total:
            continue
        mean = spec_divide(total, entry.weight)
        price = mean if mean < sample else sample
        if price > entry.cap:
            continue
        events.append(("convert", EX + FIELD_SPOT_META, index, to_bits(price)))
        status, raw = case.prices.get(position, (OK_STATUS, 2400000))
        if status != OK_STATUS:
            events.append(("drop error", error_body(status).hex()))
            continue
        events.append(("tick", EX + FIELD_SPOT_META, index, raw))
        step = case.ticks.get(position, 1)
        rounded = raw // step * step
        limit = rounded if rounded else 1
        events.append(("lookup", EX + FIELD_USER_MAP, FE_USER.hex()))
        if entry.amount > balances.get(quote, 0):
            continue
        order = order_record(entry.amount // limit, limit, time_millis(case.now))
        events.append(("place", book, EX, EVENTS, order))
        kind = case.places.get(position, ("ok", 0, None))
        if kind[0] == "err":
            continue
        fills, rows = kind[1], kind[2]
        if fills:
            events.append(("free", UNMAPPED + position, fills * FILL_STRIDE, 0))
        size = len(rows) if rows else 0
        events.append(("map walk", 1 if rows is not None else 0, size))
        for spot, cap in enumerate(rows or ()):
            if cap:
                events.append(("free", UNMAPPED + 0x1000 + spot, cap * 8, 0))
    return finish()


def order_record(size, price, millis):
    """The 0xd0 record `0x26cc730` gets, with every byte the cycle does not write still at the mark."""
    body = bytearray([STACK_MARK]) * 0xD0
    for at, width, value in ((0, 8, 1), (8, 8, size), (0x10, 8, 0), (0x20, 8, 0), (0x30, 8, 0), (0x38, 8, 8), (0x40, 8, 0), (0x48, 8, 0), (0x70, 8, 0),
                             (0x80, 8, price), (0x88, 8, millis), (0x90, 2, 0), (0xA2, 1, 0), (0xA8, 8, 0), (0xCC, 1, 0)):
        body[at:at + width] = value.to_bytes(width, "little")
    body[0xB8:0xCC] = FE_USER
    return bytes(body).hex()


class DriverCase:
    def __init__(self, label, gate=0, tree=1, markets=(), flag=0, now=NOW, period=86400000, last=0, network=0, statuses=None, ff_map=(), ff_depth=0, alloc_fails=False):
        self.label, self.gate, self.tree, self.markets, self.flag = label, gate, tree, markets, flag
        self.now, self.period, self.last, self.network = now, period, last, network
        self.statuses = statuses or {}
        self.ff_map, self.ff_depth, self.alloc_fails = ff_map, ff_depth, alloc_fails


DRIVER_VEC = (5, UNMAPPED + 0x2000, 3)


def spec_driver(case, image=None):
    """Predict the edge calls and the last-bucket field of one run of the driver."""
    events = []
    last = case.last
    if case.gate:
        return {"events": events, "last": last, "stop": None}
    if case.tree and case.markets:
        size = len(case.markets) << 4
        events.append(("alloc", size))
        if case.alloc_fails:
            return {"events": events, "last": last, "stop": ("alloc failed", 8, size)}
        rows = []
        for index, (market, balance) in enumerate(case.markets):
            events.append(("balance", MARKETS + index * MARKET_STRIDE, FE_USER.hex()))
            rows.append((market, max(balance - TRANSFER_FLOOR, 0)))
        for index, (market, amount) in enumerate(rows):
            events.append(("transfer", DRIVER_FRAME + 0xA8, EX, market, FE_USER.hex(), 1, amount))
            status = case.statuses.get(index, OK_STATUS)
            if status != OK_STATUS:
                events.append(("drop transfer", error_body(status).hex()))
        events.append(("free", HEAP_ALLOC, size, 0))
    events.append(("lookup", EX + FIELD_USER_MAP, FF_USER.hex()))
    if case.flag:
        events.append(("ensure", EX + FIELD_PERIOD, EX + FIELD_SPOT_BOOKS, EX, DRIVER_EVENTS))
    else:
        bucket = time_millis(case.now) // case.period
        rolled = bucket > last
        if rolled:
            last = bucket
        events.append(("span", SPAN_NAME, len(SPAN_NAME_TEXT), int(rolled), EX + FIELD_PERIOD, EX + FIELD_SPOT_BOOKS, EX, DRIVER_EVENTS))
    events.append(("cycle", EX + FIELD_TREE, case.network, EX + FIELD_SPOT_BOOKS, EX, DRIVER_EVENTS, (0, 8, 0)))
    events.append(("flush", DRIVER_VEC, EX))
    return {"events": events, "last": last, "stop": None}


# ---- harness: real bytes, edges stubbed, every edge argument recorded ----

HEAP_ALLOC = BUMP + 0x100000


class Harness:
    def __init__(self, image):
        self.image = image
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        machine = Machine(image)
        self.machine = machine
        machine.real = frozenset((BEST,))
        for slot in (SLOT_ELAPSED, SLOT_CONVERT, SLOT_LOOKUP, SLOT_FREE, SLOT_ALLOC, SLOT_ALLOC_FAILED, SLOT_BALANCE, SLOT_PANIC, SLOT_BOUNDS, SLOT_OVERFLOW):
            machine.memory.statics[slot] = self.relative[slot]
        machine.slots = {
            self.relative[SLOT_ELAPSED]: self.on_elapsed, self.relative[SLOT_CONVERT]: self.on_convert, self.relative[SLOT_LOOKUP]: self.on_lookup,
            self.relative[SLOT_FREE]: self.on_free, self.relative[SLOT_ALLOC]: self.on_alloc, self.relative[SLOT_ALLOC_FAILED]: self.on_alloc_failed,
            self.relative[SLOT_BALANCE]: self.on_balance, self.relative[SLOT_PANIC]: self.on_panic, self.relative[SLOT_BOUNDS]: self.on_bounds,
            self.relative[SLOT_OVERFLOW]: self.on_overflow}
        machine.calls = {CANCEL: self.on_cancel, TICK: self.on_tick, PLACE: self.on_place, MAP_NEXT: self.on_map_next, DROP_ERROR: self.on_drop_error,
                         TRANSFER: self.on_transfer, TRANSFER_DROP: self.on_transfer_drop, ENSURE: self.on_ensure, SPAN: self.on_span, CYCLE: self.on_cycle, FLUSH: self.on_flush}
        self.top = HEAP_SIZE
        self.bump = BUMP
        self.events = []
        self.case = None
        self.position = -1
        self.map_rows = ()
        self.map_at = 0
        self.lookup_at = 0

    # layout helpers

    def alloc(self, size):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_ALLOC:
            raise Halt("harness heap too small")
        return at

    def put(self, addr, width, value):
        self.machine.memory.write(addr, width, value & MASK.get(width, (1 << (8 * width)) - 1))

    def fresh(self):
        self.machine.memory.reset(self.top)
        self.top = HEAP_ALLOC + 0x1000
        self.bump = BUMP
        self.events = []
        self.position = -1

    def put_time(self, moment):
        for at, value in zip((0, 4, 8), moment):
            self.put(EX + FIELD_TIME + at, 4, value)

    def entry_node(self, parent, slot, rows, edges=None):
        node = self.alloc(ENTRY_NODE["size"])
        self.put(node + ENTRY_NODE["parent"], 8, parent)
        self.put(node + ENTRY_NODE["index"], 2, slot)
        self.put(node + ENTRY_NODE["length"], 2, len(rows))
        for index, row in enumerate(rows):
            self.put(node + ENTRY_NODE["keys"] + index * 8, 8, row.key)
            self.machine.memory.put_bytes(node + ENTRY_NODE["values"] + index * ENTRY_SIZE, row.pack())
            self.placed.append((node + ENTRY_NODE["values"] + index * ENTRY_SIZE, row))
        for index in range(12):
            self.put(node + ENTRY_NODE["edges"] + index * 8, 8, UNMAPPED)
        return node

    def link(self, node, slot, child):
        self.put(node + ENTRY_NODE["edges"] + slot * 8, 8, child)
        self.put(child + ENTRY_NODE["parent"], 8, node)
        self.put(child + ENTRY_NODE["index"], 2, slot)

    def spine(self, height, rows):
        """A chain of `height` keyless nodes above one leaf; returns (top, leaf)."""
        leaf = self.entry_node(0, 0, rows)
        node = leaf
        for _ in range(height):
            top = self.entry_node(0, 0, ())
            self.link(top, 0, node)
            node = top
        return node, leaf

    def build_tree(self, case):
        """Lay out the config tree. Keyless nodes are harness shapes that reach the long walks."""
        self.placed = []
        rows = case.entries
        shape = case.shape
        if shape == "flat":
            root = self.entry_node(0, 0, rows)
            height = 0
        elif shape == "two":
            root = self.entry_node(0, 0, rows[1:2] + rows[3:4])
            self.link(root, 0, self.entry_node(root, 0, rows[:1]))
            self.link(root, 1, self.entry_node(root, 1, rows[2:3]))
            self.link(root, 2, self.entry_node(root, 2, rows[4:]))
            height = 1
        else:
            height = shape
            left, _ = self.spine(height - 1, rows[:1])
            right, _ = self.spine(height - 1, rows[2:])
            root = self.entry_node(0, 0, rows[1:2])
            self.link(root, 0, left)
            self.link(root, 1, right)
        base = EX + FIELD_TREE
        self.put(base, 8, root if case.header else 0)
        self.put(base + 8, 8, height)
        self.put(base + 0x10, 8, case.claimed)
        self.order = self.placed if shape == "flat" else None
        self.place_map = {id(row): at for at, row in self.placed}

    def side_tree(self, base, shape):
        """Lay out one side tree of a book: None, "empty", or a key with a depth."""
        if shape is None:
            self.put(base, 8, 0)
            self.put(base + 8, 8, 0)
            self.put(base + 0x10, 8, 0)
            return
        key, depth = shape if isinstance(shape, tuple) else (shape, 0)
        leaf = self.alloc(SIDE_NODE["size"])
        self.put(leaf + SIDE_NODE["length"], 2, 0 if key == "empty" else 1)
        if key != "empty":
            self.put(leaf + SIDE_NODE["keys"], 8, key)
        node = leaf
        for _ in range(depth):
            top = self.alloc(SIDE_NODE["size"])
            self.put(top + SIDE_NODE["edges"], 8, node)
            node = top
        self.put(base, 8, node)
        self.put(base + 8, 8, depth)
        self.put(base + 0x10, 8, 0 if key == "empty" else 1)

    def balance_tree(self, rows, depth):
        """A balance tree; depth 1 spreads the keys over one root and two leaves."""
        rows = sorted(rows)

        def node(items):
            at = self.alloc(BALANCE_NODE["size"])
            self.put(at + BALANCE_NODE["length"], 2, len(items))
            for index, (key, value) in enumerate(items):
                self.put(at + BALANCE_NODE["keys"] + index * 8, 8, key)
                self.put(at + BALANCE_NODE["values"] + index * BALANCE_NODE["stride"], 8, value)
            # Slots past the length hold a tempting key, so a wrong length reads as a hit.
            for index in range(len(items), 11):
                self.put(at + BALANCE_NODE["keys"] + index * 8, 8, 1)
                self.put(at + BALANCE_NODE["values"] + index * BALANCE_NODE["stride"], 8, 1 << 50)
            return at
        if not depth or len(rows) < 3:
            return node(rows), 0
        middle = len(rows) // 2
        root = node(rows[middle:middle + 1])
        self.put(root + BALANCE_NODE["edges"], 8, node(rows[:middle]))
        self.put(root + BALANCE_NODE["edges"] + 8, 8, node(rows[middle + 1:]))
        return root, 1

    def lookup_record(self, rows, depth):
        record = self.alloc(0x20)
        if rows:
            root, height = self.balance_tree(rows, depth)
            self.put(record + 0x10, 8, root)
            self.put(record + 0x18, 8, height)
        else:
            self.put(record + 0x10, 8, 0)
            self.put(record + 0x18, 8, 0)
        return record

    # stubs

    def on_cancel(self, m):
        book = m.regs[RDI]
        self.position += 1
        self.book_index = (book - BOOKS) // BOOK_STRIDE
        user = m.memory.bytes_at(m.regs[RSI], 20).hex()
        self.events.append(("cancel", book, user, m.regs[RDX] & 0xFF, m.regs[RCX], m.regs[R8], m.regs[R9] & 0xFF))

    def on_elapsed(self, m):
        now = struct.unpack("<III", m.memory.bytes_at(m.regs[RDI], 12))
        word, line = struct.unpack("<II", m.memory.bytes_at(m.regs[RSI] + 0x10, 8))
        pointer, size = struct.unpack("<QQ", m.memory.bytes_at(m.regs[RSI] + 0x18, 16))
        self.events.append(("elapsed", now, struct.unpack("<III", m.memory.bytes_at(m.regs[RSI], 12)), word, line, pointer, size))
        m.xmm[0] = to_bits(self.case.elapsed.get(self.position, 1.0))
        m.keep_float = True

    def on_convert(self, m):
        self.events.append(("convert", m.regs[RSI], m.regs[RDX], m.xmm[0] & MASK[8]))
        status, raw = self.case.prices.get(self.position, (OK_STATUS, 2400000))
        out = m.regs[RDI]
        if status == OK_STATUS:
            self.put(out, 2, status)
            self.put(out + 8, 8, raw)
        else:
            m.memory.put_bytes(out, error_body(status))
        m.regs[RAX] = out

    def on_drop_error(self, m):
        self.events.append(("drop error", m.memory.bytes_at(m.regs[RDI], 0x60).hex()))

    def on_tick(self, m):
        self.events.append(("tick", m.regs[RDI], m.regs[RSI], m.regs[RDX]))
        m.regs[RAX] = self.case.ticks.get(self.position, 1)

    def on_lookup(self, m):
        self.events.append(("lookup", m.regs[RDI], m.memory.bytes_at(m.regs[RSI], 20).hex()))
        m.regs[RAX] = self.lookup_at

    def on_place(self, m):
        record = m.memory.bytes_at(m.regs[RSI], 0xD0).hex()
        self.events.append(("place", m.regs[RDX], m.regs[RCX], m.regs[R8], record))
        out = m.regs[RDI]
        kind = self.case.places.get(self.position, ("ok", 0, None))
        if kind[0] == "err":
            self.put(out, 8, NICHE)
            self.put(out + 8, 8, 0x41)
        else:
            fills, rows = kind[1], kind[2]
            self.put(out, 8, fills)
            self.put(out + 8, 8, UNMAPPED + self.position)
            self.put(out + 0x10, 8, 0)
            self.put(out + 0x18, 8, UNMAPPED + 0x800 if rows is not None else 0)
            self.put(out + 0x20, 8, 7)
            self.put(out + 0x28, 8, len(rows) if rows else 0)
            self.map_rows = rows or ()
            self.map_at = 0
            self.map_first = True
        m.regs[RAX] = out

    def on_map_next(self, m):
        walker = m.regs[RSI]
        if self.map_first:
            self.map_first = False
            tag = m.memory.read(walker, 8)
            other = m.memory.read(walker + 0x20, 8)
            size = m.memory.read(walker + 0x40, 8)
            if tag != other:
                raise Halt("map walker tags differ")
            if tag:
                shape = (m.memory.read(walker + 8, 8), m.memory.read(walker + 0x10, 8), m.memory.read(walker + 0x18, 8), m.memory.read(walker + 0x28, 8),
                         m.memory.read(walker + 0x30, 8), m.memory.read(walker + 0x38, 8))
                if shape != (0, UNMAPPED + 0x800, 7, 0, UNMAPPED + 0x800, 7):
                    raise Halt("map walker fields")
            self.events.append(("map walk", tag, size))
        out = m.regs[RDI]
        if self.map_at >= len(self.map_rows):
            self.put(out, 8, 0)
            return
        node = self.alloc(0x210)
        at = self.map_at * 0x18
        self.put(node + at + 8, 8, self.map_rows[self.map_at])
        self.put(node + at + 0x10, 8, UNMAPPED + 0x1000 + self.map_at)
        self.put(out, 8, node)
        self.put(out + 8, 8, 0)
        self.put(out + 0x10, 8, self.map_at)
        self.map_at += 1

    def on_free(self, m):
        self.events.append(("free", m.regs[RDI], m.regs[RSI], m.regs[RDX] & MASK[8]))

    def on_alloc(self, m):
        self.events.append(("alloc", m.regs[RDI]))
        m.regs[RAX] = 0 if self.case.alloc_fails else HEAP_ALLOC

    def on_alloc_failed(self, m):
        raise Panicked(("alloc failed", m.regs[RDI], m.regs[RSI]))

    def on_balance(self, m):
        market = m.regs[RDI]
        self.events.append(("balance", market, m.memory.bytes_at(m.regs[RSI], 20).hex()))
        m.regs[RAX] = self.case.markets[(market - MARKETS) // MARKET_STRIDE][1]

    def on_transfer(self, m):
        self.position += 1
        self.events.append(("transfer", m.regs[RDI], m.regs[RSI], m.regs[RDX], m.memory.bytes_at(m.regs[RCX], 20).hex(), m.regs[R8], m.regs[R9]))
        status = self.case.statuses.get(self.position, OK_STATUS)
        if status == OK_STATUS:
            self.put(m.regs[RDI], 2, status)
        else:
            m.memory.put_bytes(m.regs[RDI], error_body(status))

    def on_transfer_drop(self, m):
        self.events.append(("drop transfer", m.memory.bytes_at(m.regs[RDI], 0x60).hex()))

    def on_ensure(self, m):
        self.events.append(("ensure", m.regs[RDI], m.regs[RSI], m.regs[RDX], m.regs[RCX]))

    def on_span(self, m):
        head = m.regs[RDI]
        body = m.regs[RSI]
        if m.memory.bytes_at(head + 0x10, 16) != bytes(self.image.blob[self.image.offset(SPAN_OPTIONS):self.image.offset(SPAN_OPTIONS) + 16]):
            raise Halt("span options")
        self.events.append(("span", m.memory.read(head, 8), m.memory.read(head + 8, 8), m.memory.read(head + 0x20, 1), m.memory.read(body, 8),
                            m.memory.read(body + 8, 8), m.memory.read(body + 0x10, 8), m.memory.read(body + 0x18, 8)))

    def on_cycle(self, m):
        self.events.append(("cycle", m.regs[RDI], m.regs[RSI] & 0xFF, m.regs[RDX], m.regs[RCX], m.regs[R8],
                            struct.unpack("<QQQ", m.memory.bytes_at(m.regs[R8], 24))))
        for at, value in enumerate(DRIVER_VEC):
            self.put(m.regs[R8] + at * 8, 8, value)

    def on_flush(self, m):
        self.events.append(("flush", struct.unpack("<QQQ", m.memory.bytes_at(m.regs[RDI], 24)), m.regs[RSI]))

    def on_panic(self, m):
        raise Panicked(("panic", m.regs[RDI]))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_overflow(self, m):
        raise Panicked(("overflow", m.regs[RDI]))

    # runs

    def run_cycle(self, case, argument=0):
        self.fresh()
        self.case = case
        self.build_tree(case)
        put = self.put
        put(EX + FIELD_SPOT_BOOKS + 8, 8, BOOKS)
        put(EX + FIELD_SPOT_BOOKS + 0x10, 8, case.book_count)
        self.put_time(case.now)
        put(EX + FIELD_PAIRS, 8, PAIRS)
        put(EX + FIELD_PAIRS + 8, 8, len(case.pairs))
        put(EX + FIELD_PAIRS + 0x10, 8, 0)
        put(EX + FIELD_TOKENS, 8, TOKENS)
        put(EX + FIELD_TOKENS + 8, 8, len(case.tokens))
        for index, (base, quote) in enumerate(case.pairs):
            put(PAIRS + index * PAIR_STRIDE, 8, base)
            put(PAIRS + index * PAIR_STRIDE + 8, 8, quote)
        for index, (first, second) in enumerate(case.tokens):
            put(TOKENS + index * TOKEN_STRIDE + 0x48, 1, first)
            put(TOKENS + index * TOKEN_STRIDE + 0x49, 1, second)
        for index in range(min(case.book_count, 12)):
            shape = case.books.get(index, DEFAULT_BOOK)
            self.side_tree(BOOKS + index * BOOK_STRIDE + 0x80, shape[:1][0] if shape[0] is None or shape[0] == "empty" else (shape[0], shape[2]))
            self.side_tree(BOOKS + index * BOOK_STRIDE + 0x98, (shape[1], 0) if shape[1] is not None else None)
        self.lookup_at = self.lookup_record(case.balances, case.balance_depth)
        stop = None
        machine = self.machine
        try:
            machine.run(CYCLE, {RDI: EX + FIELD_TREE, RSI: argument, RDX: EX + FIELD_SPOT_BOOKS, RCX: EX, R8: EVENTS})
        except Panicked as caught:
            stop = caught.args[0]
        rows = [machine.memory.bytes_at(self.place_map[id(row)], ENTRY_SIZE) for row in case.entries]
        return {"events": self.events, "entries": rows, "stop": stop}

    def run_driver(self, case):
        self.fresh()
        self.case = case
        put = self.put
        put(EX + FIELD_GATE, 1, case.gate)
        put(EX + FIELD_TREE + 0x10, 8, case.tree)
        put(EX + FIELD_MARKETS, 8, MARKETS)
        put(EX + FIELD_MARKETS + 8, 8, len(case.markets))
        for index, (market, _) in enumerate(case.markets):
            put(MARKETS + index * MARKET_STRIDE + 0x30, 8, market)
        self.put_time(case.now)
        put(EX + FIELD_PERIOD, 8, case.period)
        put(EX + FIELD_LAST, 8, case.last)
        put(EX + FIELD_NETWORK, 1, case.network)
        self.lookup_at = self.lookup_record(case.ff_map, case.ff_depth)
        stop = None
        try:
            self.machine.run(DRIVER, {RDI: EX, RSI: 0xABCD00 | case.flag})
        except Panicked as caught:
            stop = caught.args[0]
        return {"events": self.events, "last": self.machine.memory.read(EX + FIELD_LAST, 8), "stop": stop}


def compare_cycle(harness, case):
    expected = spec_cycle(case)
    try:
        actual = harness.run_cycle(case)
    except (Halt, EvidenceError, IndexError, KeyError, ZeroDivisionError) as caught:
        return "%s: crash %s" % (case.label, caught)
    for key in ("stop", "events", "entries"):
        if actual[key] != expected[key]:
            return "%s: %s differs" % (case.label, key)
    return None


def compare_driver(harness, case):
    expected = spec_driver(case)
    try:
        actual = harness.run_driver(case)
    except (Halt, EvidenceError, IndexError, KeyError, ZeroDivisionError) as caught:
        return "%s: crash %s" % (case.label, caught)
    for key in ("stop", "events", "last"):
        if actual[key] != expected[key]:
            return "%s: %s differs" % (case.label, key)
    return None


# ---- cases ----

def good(index=0, **fields):
    """An entry past its warm-up, with a mean of 2 and a previous time."""
    values = dict(total=4.0, weight=2.0, window=30.0, count=100, word=EARLIER[0], seconds=EARLIER[1], nanos=EARLIER[2])
    values.update(fields)
    return Entry(index=index, **values)


def cycle_cases():
    rich = DEFAULT_BALANCES
    rows = []

    def add(label, entries, **options):
        options.setdefault("balances", rich)
        rows.append(CycleCase(label, entries, **options))

    add("empty header root", [good()], header=False)
    add("zero length", [good()], claimed=0)
    add("no previous time, warm-up", [Entry(count=0)])
    add("no previous time, past warm-up", [Entry(window=30.0, count=100)])
    add("previous time, gates pass", [good()], elapsed={0: 2.5})
    add("zero elapsed", [good()], elapsed={0: 0.0})
    add("elapsed equals window", [good()], elapsed={0: 30.0})
    add("elapsed above window", [good()], elapsed={0: 30.0000001})
    add("elapsed above small window", [good(window=4.0)], elapsed={0: 5.0})
    add("window 10 exactly, reset", [good(window=10.0)], elapsed={0: 11.0})
    add("window above 10, reset keeps it", [good(window=25.0)], elapsed={0: 26.0})
    add("zero window, no previous time", [Entry(window=0.0)])
    add("negative window resets", [Entry(window=-3.0)])
    add("infinite window never counts", [good(window=math.inf)], elapsed={0: 1e9})
    add("not a number window", [good(window=math.nan)], elapsed={0: 1.0})
    add("not a number elapsed", [good()], elapsed={0: math.nan})
    add("count one short of window", [good(window=30.0, count=28)])
    add("count reaches window", [good(window=30.0, count=29)])
    add("count passes window", [good(window=30.0, count=30)])
    add("count at top saturates", [good(window=30.0, count=MASK[8])])
    add("count near top", [good(window=30.0, count=MASK[8] - 1)])
    add("large window, count in low word", [good(window=4294967300.0, count=4294967296)])
    still = dict(window=1e19, count=MASK[8])
    add("weight at floor", [good(weight=1e-15, total=2e-15, **still)], elapsed={0: 0.0})
    add("weight under floor", [good(weight=f64_below(1e-15), total=2e-15, **still)], elapsed={0: 0.0})
    add("weight negative", [good(weight=-1.0, **still)], elapsed={0: 0.0})
    add("weight not a number", [good(weight=math.nan, **still)], elapsed={0: 0.0})
    add("sum zero", [good(total=0.0, **still)], elapsed={0: 0.0})
    add("sum at negative floor", [good(total=-1e-15, **still)], elapsed={0: 0.0})
    add("sum just inside floor", [good(total=f64_above(-1e-15), **still)], elapsed={0: 0.0})
    add("sum just outside floor", [good(total=f64_below(-1e-15), **still)], elapsed={0: 0.0})
    add("sum negative", [good(total=-5.0, **still)], elapsed={0: 0.0})
    add("sum tiny positive", [good(total=1e-16, **still)], elapsed={0: 0.0})
    add("mean under sample", [good(total=1.0, weight=2.0, **still)], elapsed={0: 0.0})
    add("mean over sample", [good(total=1e9, weight=2.0, **still)], elapsed={0: 0.0})
    add("mean equals sample", [good(total=5000.0, weight=2.0, **still)], elapsed={0: 0.0}, books={0: (-2500000, 2510000, 0)})
    add("price over cap", [good(total=4.0, weight=2.0, cap=1.5, **still)], elapsed={0: 0.0})
    add("price equals cap", [good(total=4.0, weight=2.0, cap=2.0, **still)], elapsed={0: 0.0})
    add("price under cap", [good(total=4.0, weight=2.0, cap=2.5, **still)], elapsed={0: 0.0})
    add("sample decides cap", [good(total=1e12, weight=2.0, cap=2499.0, **still)], elapsed={0: 0.0})
    add("sample at cap", [good(total=1e12, weight=2.0, cap=2500.0, **still)], elapsed={0: 0.0})
    add("cap not a number", [good(cap=math.nan)])
    for scale_index in (0, 2, 3, 4, 5, 6):
        add("scale of pair %d" % scale_index, [good(scale_index, total=3.5, weight=7.0)], elapsed={0: 1.5})
    add("top key positive", [good()], books={0: (2500000, 2510000, 0)})
    add("top key large", [good()], books={0: (-(1 << 62) - 12345, 2510000, 0)})
    add("top key low bits", [good()], books={0: (-4294967297, 2510000, 0)})
    add("top key at depth 1", [good()], books={0: (-2400000, 2510000, 1)})
    add("top key at depth 3", [good()], books={0: (-2400000, 2510000, 3)})
    add("top key at depth 8", [good()], books={0: (-2400000, 2510000, 8)})
    add("top key at depth 9", [good()], books={0: (-2400000, 2510000, 9)})
    add("other side empty", [good()], books={0: (-2500000, None, 0)})
    add("no top key, previous state", [good()], books={0: (None, 2510000, 0)})
    add("empty tree, previous state", [good()], books={0: ("empty", 2510000, 0)})
    add("zero key", [good()], books={0: (0, 2510000, 0)})
    add("no top key then next entry", [good(0), good(3)], books={0: (None, 2510000, 0)})
    add("convert fails", [good()], prices={0: (0xAC, 0)})
    add("convert other status", [good()], prices={0: (0x187, 0)})
    add("convert status with low byte of success", [good()], prices={0: (0x286, 0)})
    add("convert fails then next entry", [good(0), good(3)], prices={0: (0xAC, 0)})
    add("tick one", [good()], prices={0: (OK_STATUS, 2413579)}, ticks={0: 1})
    add("tick rounds down", [good()], prices={0: (OK_STATUS, 2413579)}, ticks={0: 100})
    add("tick exact multiple", [good()], prices={0: (OK_STATUS, 2413500)}, ticks={0: 100})
    add("tick above price lifts to one", [good(amount=5000)], prices={0: (OK_STATUS, 50)}, ticks={0: 100})
    add("price zero lifts to one", [good(amount=5000)], prices={0: (OK_STATUS, 0)}, ticks={0: 100})
    add("price in high word", [good()], prices={0: (OK_STATUS, (1 << 40) + 77777)}, ticks={0: 1000})
    add("tick in high word", [good()], prices={0: (OK_STATUS, (1 << 41) + 3)}, ticks={0: 1 << 33})
    add("price over top bit", [good()], prices={0: (OK_STATUS, MASK[8])}, ticks={0: 3})
    add("amount equals balance", [good(amount=500)], balances=((1, 500),))
    add("amount over balance", [good(amount=501)], balances=((1, 500),))
    add("amount under balance", [good(amount=499)], balances=((1, 500),))
    add("balance of the wrong token", [good(amount=500)], balances=((0, 500), (2, 500),))
    add("balance tree absent", [good(amount=500)], balances=())
    add("amount zero, tree absent", [good(amount=0)], balances=())
    add("amount zero, key absent", [good(amount=0)], balances=((0, 500),))
    add("amount in high word", [good(amount=(1 << 36) + 5)], balances=((1, 1 << 37),))
    add("balance key first of many", [good(1, amount=500) if False else good(amount=500)], balances=((1, 500), (5, 1), (7, 2)))
    add("balance key last of many", [good(amount=500)], balances=((0, 7), (1, 500)))
    add("balance key missing in the gap", [good(amount=500)], balances=((0, 7), (2, 500), (3, 500)))
    add("balance key past the end", [good(amount=500)], balances=((0, 7),))
    add("balance at depth 1, left", [good(amount=500)], balances=((1, 500), (2, 1), (3, 1)), balance_depth=1)
    add("balance at depth 1, root", [good(amount=500)], balances=((0, 1), (1, 500), (2, 1)), balance_depth=1)
    add("balance at depth 1, right", [good(amount=500)], balances=((0, 1), (0x100, 1), (1, 500)) and ((0, 1), (1, 500), (2, 1), (3, 1)), balance_depth=1)
    add("balance at depth 1, absent", [good(amount=500)], balances=((0, 500), (2, 500), (3, 500)), balance_depth=1)
    add("size floors", [good(amount=7000001)], prices={0: (OK_STATUS, 3000000)})
    add("size zero under one price", [good(amount=7)], prices={0: (OK_STATUS, 3000000)})
    add("size with both words high", [good(amount=(1 << 38) + 9)], prices={0: (OK_STATUS, (1 << 33) + 1)}, balances=((1, 1 << 39),))
    add("place rejected", [good()], places={0: ("err",)})
    add("place rejected then next entry", [good(0), good(3)], places={0: ("err",)})
    add("place no fills", [good()], places={0: ("ok", 0, None)})
    add("place fills", [good()], places={0: ("ok", 3, None)})
    add("place map rows", [good()], places={0: ("ok", 0, (2, 0, 5))})
    add("place fills and rows", [good()], places={0: ("ok", 1, (4,))})
    add("place empty map", [good()], places={0: ("ok", 2, ())})
    add("place twice", [good(0), good(3)], places={0: ("ok", 3, (1,)), 1: ("ok", 1, None)})
    add("book past the end", [good(9)])
    add("book at the last index", [good(7)], book_count=8)
    add("book count zero", [good(0)], book_count=0)
    add("second entry past the books", [good(0), good(9)])
    add("pair past the end", [good(4)], pairs=DEFAULT_PAIRS[:4])
    add("pair at the last index", [good(3)], pairs=DEFAULT_PAIRS[:4])
    add("quote token past the end", [good(0)], pairs=((0, 4),))
    add("base token past the end", [good(0)], pairs=((4, 1),))
    add("quote token at the last index", [good(0)], pairs=((0, 3),))
    add("base token at the last index", [good(0)], pairs=((3, 3),))
    add("scale negative", [good(1)])
    add("scale zero", [good(0)], pairs=((3, 0),), tokens=((0, 8), (0, 6), (8, 8), (8, 8)))
    add("claimed past the tree", [good(0)], claimed=2)
    add("claimed past deep tree", [good(0), good(3), good(4)], shape=2, claimed=4)
    add("eleven entries", [good(index % 8) for index in range(11)])
    add("two levels", [good(0), good(2), good(3), good(4), good(5), good(6)], shape="two")
    for height in (1, 2, 3, 7, 8, 9, 10, 15, 16, 17):
        add("spine height %d" % height, [good(0), good(3), good(4)], shape=height)
    add("spine height 3, wider leaf", [good(0), good(3), good(4), good(5)], shape=3)
    for year, day, seconds, nanos in ((1970, 1, 0, 0), (1970, 1, 0, 999999), (1970, 1, 0, 1000000), (1970, 2, 1, 1999999999), (2026, 303, 86399, 999999999),
                                      (2024, 366, 0, 0), (1969, 365, 86399, 0), (1, 1, 0, 0), (0, 1, 0, 0), (-1, 365, 0, 0), (-400, 1, 0, 0), (-5000, 200, 7, 0),
                                      (262000, 1, 5, 0), (400, 366, 0, 0)):
        add("time %d day %d" % (year, day), [good()], now=(pack_date(year, day), seconds, nanos))
    add("year on a hundred", [good()], now=(pack_date(2001, 1), 5, 0))
    add("year on four hundred", [good()], now=(pack_date(2401, 60), 5, 0))
    add("year on a hundred, not four", [good()], now=(pack_date(2101, 60), 5, 0))
    add("previous time with zero nanos", [good(nanos=0)], elapsed={0: 2.5})
    add("no previous time, nanos left over", [good(word=0, nanos=7, seconds=9)], elapsed={0: 25.0})
    add("price just over the low word", [good()], prices={0: (OK_STATUS, (1 << 32) + 7)}, ticks={0: 3})
    add("amount just over the low word", [good(amount=(1 << 32) + 5)], prices={0: (OK_STATUS, 3)})
    add("mean sequence", [good(total=0.0, weight=0.0, count=40)], elapsed={0: 0.4})
    return rows


def driver_cases():
    rows = [
        DriverCase("gate set", gate=1, markets=((3, 5 << 30),)),
        DriverCase("gate other byte", gate=2),
        DriverCase("empty tree", tree=0, markets=((3, 5 << 30),)),
        DriverCase("no markets"),
        DriverCase("one market", markets=((3, 5 << 30),)),
        DriverCase("floor plus one", markets=((3, TRANSFER_FLOOR + 1),)),
        DriverCase("floor exactly", markets=((3, TRANSFER_FLOOR),)),
        DriverCase("under the floor", markets=((3, TRANSFER_FLOOR - 1),)),
        DriverCase("zero balance", markets=((3, 0),)),
        DriverCase("three markets", markets=((3, 5 << 30), (0, 1 << 40), (9, 7))),
        DriverCase("transfer fails", markets=((3, 5 << 30),), statuses={0: 0xC4}),
        DriverCase("second transfer fails", markets=((3, 5 << 30), (0, 1 << 40), (9, 1 << 33)), statuses={1: 0xC4}),
        DriverCase("status with low byte of success", markets=((3, 5 << 30),), statuses={0: 0x286}),
        DriverCase("allocation fails", markets=((3, 5 << 30), (0, 1)), alloc_fails=True),
        DriverCase("flag set", flag=1, last=1 << 50),
        DriverCase("flag and sweep", flag=1, markets=((3, 5 << 30),)),
        DriverCase("bucket rolled", last=0),
        DriverCase("bucket equal", period=86400000, last=time_millis(NOW) // 86400000),
        DriverCase("bucket one behind", period=86400000, last=time_millis(NOW) // 86400000 - 1),
        DriverCase("bucket ahead", period=86400000, last=time_millis(NOW) // 86400000 + 1),
        DriverCase("period in low word, small time", now=(pack_date(1970, 1), 1000, 0), period=60000, last=5),
        DriverCase("period in low word, equal", now=(pack_date(1970, 1), 1000, 0), period=60000, last=16),
        DriverCase("period in low word, one behind", now=(pack_date(1970, 1), 1000, 0), period=60000, last=15),
        DriverCase("period in high word", period=1 << 33, last=0),
        DriverCase("time clamps to zero", now=(pack_date(1969, 1), 0, 0), last=0),
        DriverCase("time year 0", now=(pack_date(0, 1), 0, 0), last=0),
        DriverCase("time year -400", now=(pack_date(-400, 20), 3, 0), last=0),
        DriverCase("time with nanos", now=(pack_date(1970, 2), 3, 7654321), period=1000, last=86402),
        DriverCase("network byte set", network=2),
        DriverCase("high marker balance map", ff_map=((0, 9),)),
        DriverCase("high marker map, key zero missing", ff_map=((4, 9), (5, 1))),
        DriverCase("high marker map, deep", ff_map=((0, 9), (2, 1), (4, 1)), ff_depth=1),
        DriverCase("high marker map, deep, zero absent", ff_map=((1, 9), (2, 1), (4, 1)), ff_depth=1),
    ]
    for year, day, seconds, nanos in ((1970, 1, 7, 0), (2001, 1, 5, 0), (2024, 366, 86399, 999999999), (2401, 60, 1, 0), (2101, 60, 1, 0), (2026, 303, 3, 5000000), (1970, 60, 0, 0)):
        rows.append(DriverCase("whole time, year %d" % year, now=(pack_date(year, day), seconds, nanos), period=1))
    rows.append(DriverCase("time just over the low word", now=(pack_date(1970, 60), 0, 0), period=3))
    return rows


# ---- structure of the bytes ----

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


def find_all(image, start, pattern):
    """Every place a byte pattern occurs inside a function."""
    begin, end = image.exact_fde(start)
    data = bytes(image.blob[image.offset(begin):image.offset(begin) + end - begin])
    found = []
    at = data.find(pattern)
    while at >= 0:
        found.append(begin + at)
        at = data.find(pattern, at + 1)
    return found


# Each row: function, meaning, byte pattern, expected number of sites.
PINS = (
    (CYCLE, "imul r15, rcx, 0xd8: book stride", b"\x4c\x69\xf9\xd8\x00\x00\x00", 1),
    (CYCLE, "mov dword [..], 0xfefefefe: tail of the user literal, in the cancel, the lookup and the order", b"\xfe\xfe\xfe\xfe", 3),
    (CYCLE, "mov edx, 1 then the cancel arguments: flag 1", b"\xba\x01\x00\x00\x00\x4c\x89\xd1", 1),
    (CYCLE, "mov r9d, 2: cancel reason 2", b"\x41\xb9\x02\x00\x00\x00", 1),
    (CYCLE, "movabs rax, 0x5400000001: tag 1, line 84 of time.rs", b"\x48\xb8\x01\x00\x00\x00\x54\x00\x00\x00", 1),
    (CYCLE, "cmp word [rsp+0xe0], 0x186: success status", b"\x66\x81\xbc\x24\xe0\x00\x00\x00\x86\x01", 1),
    (CYCLE, "imul rsi, rax, 0x228: fill stride", b"\x48\x69\xf0\x28\x02\x00\x00", 1),
    (CYCLE, "imul rcx, rcx, 0xe8: token stride, quote", b"\x48\x69\xc9\xe8\x00\x00\x00", 1),
    (CYCLE, "imul rdx, rdx, 0xe8: token stride, base", b"\x48\x69\xd2\xe8\x00\x00\x00", 1),
    (DRIVER, "cmp byte [rdi+0x3ac8], 0: gate", b"\x80\xbf\xc8\x3a\x00\x00\x00", 1),
    (DRIVER, "cmp qword [rdi+0x3a10], 0: tree length", b"\x48\x83\xbf\x10\x3a\x00\x00\x00", 1),
    (DRIVER, "sub rax, 0x3b9aca00: balance floor", b"\x48\x2d\x00\xca\x9a\x3b", 1),
    (DRIVER, "add r12, 0x2f0: market stride", b"\x49\x81\xc4\xf0\x02\x00\x00", 1),
    (DRIVER, "mov r8d, 1: transfer flag, and the year arm", b"\x41\xb8\x01\x00\x00\x00", 2),
    (DRIVER, "mov qword [rsp+0x48], 0x1c: span name length", b"\x48\xc7\x44\x24\x48\x1c\x00\x00\x00", 1),
    (DRIVER, "cmp word [rsp+0xa8], 0x186: success status", b"\x66\x81\xbc\x24\xa8\x00\x00\x00\x86\x01", 1),
    (SPAN, "cmp r14b, 1: the span runs its body only for flag 1", b"\x41\x80\xfe\x01", 1),
)


def read_pins(image):
    rows = []
    for start, meaning, pattern, expected in PINS:
        found = find_all(image, start, pattern)
        if len(found) != expected:
            raise EvidenceError("pin %r has %d sites" % (meaning, len(found)))
        rows.append({"function": "%#x" % start, "sites": ["%#x" % va for va in found], "bytes": pattern.hex(), "meaning": meaning})
    return rows


def read_f64(image, va):
    return struct.unpack_from("<d", image.blob, image.offset(va))[0]


def read_constants(image):
    table = list(struct.unpack_from("<23d", image.blob, image.offset(POW10)))
    if table != [10.0 ** power for power in range(23)]:
        raise EvidenceError("power table differs")
    user = bytes(image.blob[image.offset(USER_WORD):image.offset(USER_WORD) + 16])
    if user != FE_USER[:16]:
        raise EvidenceError("user literal differs")
    name = bytes(image.blob[image.offset(SPAN_NAME):image.offset(SPAN_NAME) + len(SPAN_NAME_TEXT)])
    if name != SPAN_NAME_TEXT:
        raise EvidenceError("span name differs")
    path = bytes(image.blob[image.offset(TIME_PATH):image.offset(TIME_PATH) + TIME_PATH_SIZE]).decode("ascii")
    return {"f64": {"%#x" % va: read_f64(image, va) for va in (F64_ONE, F64_TEN, F64_FLOOR, F64_NEG_FLOOR)},
            "power_table": {"va": "%#x" % POW10, "entries_checked": len(table), "last": table[-1]},
            "user_literal": {"va": "%#x" % USER_WORD, "first_16": user.hex()},
            "span_name": {"va": "%#x" % SPAN_NAME, "text": name.decode("ascii")},
            "elapsed_location": {"path": path[path.rindex("/l1/") + 1:], "line": TIME_LINE},
            "span_options": bytes(image.blob[image.offset(SPAN_OPTIONS):image.offset(SPAN_OPTIONS) + 16]).hex()}


def check_callers(image):
    """The only two direct calls of the driver, and the byte that gives each its flag."""
    sites = direct_sites(image, [DRIVER, CYCLE])
    found = sorted(va for va, _ in sites[DRIVER])
    if found != sorted(row[0] for row in CALLERS):
        raise EvidenceError("driver sites differ: %s" % found)
    if len(sites[CYCLE]) != 1 or not image.fde(sites[CYCLE][0][0])[0] == DRIVER:
        raise EvidenceError("the cycle has another caller")
    rows = []
    for site, function, flag in CALLERS:
        before = bytes(image.blob[image.offset(site - 5):image.offset(site)]) if flag else bytes(image.blob[image.offset(site - 2):image.offset(site)])
        wanted = b"\xbe\x01\x00\x00\x00" if flag else b"\x31\xf6"
        if before != wanted or image.fde(site)[0] != function:
            raise EvidenceError("flag bytes differ at %#x" % site)
        rows.append({"site": "%#x" % site, "function": "%#x" % function, "flag": flag, "bytes_before": before.hex()})
    return rows


# ---- mutation pass ----

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


def run_mutants(image, seen, verbose=False):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    for start, cases, check in ((CYCLE, cycle_cases(), compare_cycle), (DRIVER, driver_cases(), compare_driver)):
        rows = decode_range(image, *image.exact_fde(start))
        for va, at, kind in mutation_targets(image, rows):
            if va not in seen:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            for index, case in enumerate(cases):
                failed = check(harness, case)
                if failed:
                    cases.insert(0, cases.pop(index))
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"function": start, "va": va, "kind": kind, "result": "killed" if failed else "survived",
                            "by": failed.split(":")[0] if failed else ""})
            if verbose and not failed:
                print("survived %#x %s" % (va, kind), flush=True)
    return results


# ---- evidence ----

ENTRY_MAP = (
    (0x00, "f64", "decaying sum: sum * (1 - 1/window) + sample * seconds"),
    (0x08, "f64", "decaying weight: weight * (1 - 1/window) + seconds"),
    (0x10, "f64", "window; lifted to at least 10 only on reset"),
    (0x18, "u64", "samples since reset, saturating"),
    (0x20, "12 bytes", "time of the last sample; a zero first word means none"),
    (0x30, "u64", "spot pair and book index"),
    (0x38, "u64", "quote amount of one order"),
    (0x40, "f64", "price cap"),
)
RECORD_MAP = (
    (0x00, 8, "1"),
    (0x08, 8, "size: amount / limit, floored"),
    (0x38, 8, "8, the dangling pointer of an empty vector; +0x30 and +0x40 are 0"),
    (0x48, 8, "0, the first word `0x26cc730` tests"),
    (0x80, 8, "limit price, raw"),
    (0x88, 8, "time in milliseconds, clamped at 0"),
    (0x90, 2, "0, side byte and the byte tested at `0x26cc7ca`"),
    (0xA2, 1, "0"),
    (0xB8, 20, "user 0xfe * 20"),
    (0xCC, 1, "0, the byte the mid-price builders set to 1 or 4"),
)
EXCHANGE_MAP = (
    (FIELD_TIME, "block time word, 12 bytes"),
    (FIELD_USER_MAP, "user map, `0x371b3a0` key"),
    (FIELD_SPOT_META, "spot metadata; pairs at +0x1f8 of the exchange, tokens at +0x210"),
    (FIELD_MARKETS, "perp market array, stride 0x2f0, length at +0x5c8"),
    (FIELD_NETWORK, "byte passed in esi to the cycle, which never reads it"),
    (FIELD_SPOT_BOOKS, "spot book vector, pointer at +8, length at +0x10, stride 0xd8"),
    (FIELD_PERIOD, "time bucket width in milliseconds"),
    (FIELD_LAST, "last bucket seen"),
    (FIELD_TREE, "config tree: root, height, length"),
    (FIELD_GATE, "any nonzero byte skips the whole step"),
)
REFERENCE_CLAIMS = (
    {"reference": "l1/books.rs:984-997", "claim": "`0x1E83350` is ImpactState::observe: alpha = (elapsed / window).clamp(0, 1), sum and weight blended by alpha, elapsed in seconds",
     "bytes": "the factor is 1 - 1/window and does not depend on elapsed; elapsed is added as a weight; there is no clamp; elapsed above the window resets the state and drops the sample"},
    {"reference": "l1/books.rs:976-982", "claim": "reset clamps the window to at least 10 and clears last_update_ms",
     "bytes": "agrees, but the reset arm is reached only by elapsed above the window, and the window is not lifted on an update"},
    {"reference": "l1/books.rs:999-1001", "claim": "normalized returns sum / weight when weight > 1e-15",
     "bytes": "the floor is `1e-15 > weight` skips, so a weight of exactly 1e-15 passes; the sum also has a negative floor the reference does not have"},
    {"reference": "l1/books.rs (the function around the label)", "claim": "impact notional from a sample",
     "bytes": "the function walks a config tree, cancels and places orders for one user; none of this is in the reference, and neither is the 0xfe literal or the span name"},
    {"reference": "l1/exchange/handlers/59_system_usd_class_transfer.rs:93", "claim": "`0x270F6F0` is the shared class transfer path",
     "bytes": "taken as a lead only: the driver passes it a market id, the user, 1 and the amount; its body is not evaluated here"},
)
DEAD_MUL = "quotient times divisor cannot exceed the dividend, so the overflow arm has no input"
DEAD_FF = "the walk's result is unused: every arm of the 0xff lookup falls through to the same address"


def reason_for(row):
    va = row["va"]
    if row["result"] == "killed":
        return ""
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, "")


def outcome_name(spec):
    kinds = [event[0] for event in spec["events"]]
    if spec["stop"]:
        return "panic"
    if "place" in kinds:
        return "order placed"
    if "lookup" in kinds:
        return "balance short"
    if "drop error" in kinds:
        return "price conversion failed"
    if "convert" in kinds:
        return "converted, no order"
    return "gates closed or no key"


def analyse(image, full=True, verbose=False):
    harness = Harness(image)
    cycles, drivers = cycle_cases(), driver_cases()
    mismatches = []
    outcomes = {}
    argument_differences = 0
    for case in cycles:
        trouble = compare_cycle(harness, case)
        if trouble:
            mismatches.append(trouble)
        name = outcome_name(spec_cycle(case))
        outcomes[name] = outcomes.get(name, 0) + 1
    for case in drivers:
        trouble = compare_driver(harness, case)
        if trouble:
            mismatches.append(trouble)
    seen = set(harness.machine.seen)
    steps = harness.machine.steps
    for case in cycles:
        if harness.run_cycle(case, 1) != spec_cycle(case):
            argument_differences += 1
    example = next(case for case in cycles if case.label == "previous time, gates pass")
    state = harness.run_cycle(example)["entries"][0]
    total, weight = struct.unpack_from("<dd", state)
    before = example.entries[0]
    seconds = example.elapsed[0]
    sample = float(book_top(DEFAULT_BOOK)) / 1000.0
    alpha = min(seconds / before.window, 1.0)
    worked = {"sum_before": before.total, "weight_before": before.weight, "window": before.window, "seconds": seconds, "sample": sample,
              "sum_after": total, "weight_after": weight, "mean_after": total / weight,
              "reference_sum": before.total * (1.0 - alpha) + sample * alpha, "reference_weight": before.weight * (1.0 - alpha) + alpha}
    functions = []
    for role, start in (("cycle", CYCLE), ("driver", DRIVER), ("top of book reader, run real, not mutated", BEST)):
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows),
                          "instructions_stepped": sum(1 for row in rows if row.va in seen)})
    relative = harness.relative
    edges = []
    for name, target in (("cancel a user's orders in one book", CANCEL), ("place one order record", PLACE), ("tick of a raw price", TICK), ("walk of the order result map", MAP_NEXT),
                         ("drop of a conversion error", DROP_ERROR), ("class transfer path, reference label", TRANSFER), ("drop of a transfer error", TRANSFER_DROP),
                         ("hyperliquidity order step", ENSURE), ("span wrapper around that step", SPAN), ("event flush", FLUSH)):
        begin, end = image.exact_fde(target)
        edges.append({"target": "%#x" % target, "end": "%#x" % end, "meaning": name})
    sites = direct_sites(image, [CYCLE, DRIVER, BEST, CANCEL, PLACE, TICK, ENSURE, TRANSFER])
    site_rows = []
    for target in sorted(sites):
        for va, opcode in sorted(sites[target]):
            site_rows.append((target, va, opcode, image.fde(va)[0], image.fde(va)[1]))
    results_rows = run_mutants(image, seen, verbose) if full else []
    tally = {key: sum(1 for row in results_rows if row["result"] == key) for key in ("killed", "survived", "unreached")}
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "edges": edges,
        "callers": check_callers(image),
        "constants": dict(read_constants(image), transfer_floor=TRANSFER_FLOOR, reset_window_floor=read_f64(image, F64_TEN), sample_default_seconds=read_f64(image, F64_ONE)),
        "slots": {"%#x" % slot: {"target": "%#x" % relative[slot], "meaning": SLOT_NAMES[slot]} for slot in sorted(SLOT_NAMES)},
        "pins": read_pins(image),
        "locations": [{"slot": "%#x" % slot, "path": image.location(slot, relative)[0], "line": image.location(slot, relative)[1],
                       "column": image.location(slot, relative)[2]} for slot in LOCATIONS],
        "entry_map": [{"offset": "%#x" % offset, "type": kind, "meaning": meaning} for offset, kind, meaning in ENTRY_MAP],
        "record_map": [{"offset": "%#x" % offset, "size": size, "meaning": meaning} for offset, size, meaning in RECORD_MAP],
        "exchange_map": [{"offset": "%#x" % offset, "meaning": meaning} for offset, meaning in EXCHANGE_MAP],
        "nodes": {"config_tree": dict(ENTRY_NODE, value_stride=ENTRY_SIZE, capacity=11), "balance_tree": BALANCE_NODE, "side_tree": SIDE_NODE},
        "strides": {"book": BOOK_STRIDE, "pair": PAIR_STRIDE, "token": TOKEN_STRIDE, "market": MARKET_STRIDE, "fill": FILL_STRIDE},
        "worked_example": worked,
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"cycle": len(cycles), "driver": len(drivers)},
        "cycle_outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
        "argument_differences": argument_differences,
        "instructions_stepped": steps,
        "mutations": tally,
        "_sites": site_rows, "_results": results_rows,
    }


def render(evidence):
    evidence = dict(evidence)
    sites = evidence.pop("_sites")
    results = evidence.pop("_results")
    files = {"evidence.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n"}
    lines = ["target\tsite\topcode\tcaller_fde\tcaller_fde_end"]
    lines += ["%#x\t%#x\t%#x\t%#x\t%#x" % row for row in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
    lines = ["function\tva\tkind\tresult\tkilled_by\treason"]
    lines += ["%#x\t%#x\t%s\t%s\t%s\t%s" % (row["function"], row["va"], row["kind"], row["result"], row["by"], reason_for(row)) for row in results]
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


YEAR_ARM = "runs only for year <= 0; every such time is before 1970 and clamps to 0, so the arm cannot show"
YEAR_SIGN = "shifts out the sign of year - 1, which the year arm keeps at or above 0"
HEIGHT_EIGHT = "reached only with the low three bits nonzero, so height 8 never arrives and 8 and 9 compare alike"
REASON_RANGES = ((0x26FEF10, 0x26FEF73, DEAD_FF), (0x1E83D9D, 0x1E83DB8, DEAD_MUL), (0x1E83B4A, 0x1E83B72, YEAR_ARM), (0x26FEFB7, 0x26FEFDF, YEAR_ARM))
REASONS = {0x1E834C6: HEIGHT_EIGHT, 0x1E835B9: HEIGHT_EIGHT, 0x1E83B96: YEAR_SIGN, 0x26FF003: YEAR_SIGN}

if __name__ == "__main__":
    sys.exit(main())
