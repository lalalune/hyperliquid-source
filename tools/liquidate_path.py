#!/usr/bin/env python3
"""Pin the node #94 liquidate action path from ELF bytes: signer gates, three request shapes, route build and the executor.

The handler 0x23e66f0 with its copies, the route builder 0x3424d20, the agent chain 0x275f050, the executor 0x2725150 with its
copies, the event row 0x392b7b0 and the list clone 0x254e820 run whole in a Python evaluator. A separately written specification
predicts every stub argument and outcome, and every condition, immediate and field offset of the primary copy is flipped to show
the run can tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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

COPIES = (
    dict(name="primary", entry=0x23E66F0, set_insert=0x284CC30, member=0x284BB50, agent_get=0x284BC20, chain=0x275F050, map_insert=0x284FDA0, drop_set=0x28AA700, drop_route=0x28A9030, drop_map=0x28A97F0,
         run=0x2725150, clone_rows=0x254E820, clone_map=0x289BFB0, sink=0x3576710, cancel=0x26E3EF0, flush=0x24FB610, clone_positions=0x289B0B0, drop_positions=0x28A9C10, drop_info=0x277F220, order=0x2397010, send=0x26F4CD0),
    dict(name="second", entry=0x4AD4900, set_insert=0x493AC40, member=0x49277E0, agent_get=0x4927A10, chain=0x4D8BC90, map_insert=0x4938930, drop_set=0x49A9FB0, drop_route=0x49A9C60, drop_map=0x49A8FF0,
         run=0x4D2B3C0, clone_rows=0x4849E40, clone_map=0x497CAF0, sink=0x3576710, cancel=0x4303650, flush=0x4329870, clone_positions=0x499D800, drop_positions=0x49B2850, drop_info=0x4DB00F0, order=0x4A07020, send=0x4CD84F0),
    dict(name="recording", entry=0x4AD5910, set_insert=0x493AC40, member=0x49277E0, agent_get=0x4927A10, chain=0x4D8BE00, map_insert=0x4938930, drop_set=0x49A9FB0, drop_route=0x49A9C60, drop_map=0x49A8FF0,
         run=0x4D2CD20, clone_rows=0x4849E40, clone_map=0x497CAF0, sink=0x4855A50, cancel=0x4303DB0, flush=0x432A100, clone_positions=0x499D800, drop_positions=0x49B2850, drop_info=0x4DB00F0, order=0x4A07020, send=0x4CD84F0),
)
BY_NAME = {layout["name"]: layout for layout in COPIES}
ROUTE = 0x3424D20
EVENT_ROW = 0x392B7B0
CLASSIFY = 0x3C0CC70
STATUS_DROP = 0x3379490
PLAN = 0x36FFF10
USER_STATE = 0x36F57F0
DECODE = 0x3BFFFD0
BLOCK = 0x3987CB0
ITEMS = 0x3BB1420
ITER_MAP = 0x33B5620
ITER_SET = 0x33B9210
ROUTE_INSERT = 0x33A8AB0
DROP_ITER = 0x3402CF0
DROP_ASSETS = 0x33F0DA0
GROW_USERS = 0x32D64A0
PANIC_NONE = 0x157A9F0
PANIC_UNWRAP = 0x157AA10
PANIC_ADD = 0x157B480
PANIC_MUL = 0x157B4A0
OVERFLOW_LOG = 0x358DCD0
ONCE_CALL = 0x4EE3B20
ONCE_WORD = 0x577AB98
SLOT_ALLOC = 0x576DFD8
SLOT_FREE = 0x576E010
SLOT_MEMCMP = 0x576E488
SLOT_MEMCPY = 0x576DFE0
OK = 0x186
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
STEP_LIMIT = 900000
MUTANT_STEP_LIMIT = 300000
EXCHANGE = HEAP_BASE + 0x1000
BUMP = HEAP_BASE + 0x8000


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
            if value != 0:
                raise EvidenceError("unsupported compare predicate at %#x" % va)
            return finish("cmpeqsd", ("x", reg), rm, 8)
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


# ---- specification ----

RESULT_OK = 3
RESULT_ERROR = 0xE
NO_LIQUIDATOR = 0x23
DUPLICATE = 0x24
DEFAULT_LISTED = 0x25
NOT_MAIN = 0x61
NOT_AGENT = 0x7C
TOO_MANY = 0x143
WRONG_KIND = 0x15E
LIST_LIMIT = 10000
DEX_STEP = 10000
MAIN = 3
CANCEL_REASON = 13
BLOCK_TIME = bytes(range(0x31, 0x3D))
I64_MAX = (1 << 63) - 1
I64_MIN = -(1 << 63)
ROW_STRIDE = 0x68
ITEM_STRIDE = 24


def address(tail, first=0xAA):
    return bytes([first] * 19 + [tail])


def signed(word):
    return word - (1 << 64) if word >> 63 else word


def word_of(value):
    return value & MASK[8]


class Result(Exception):
    def __init__(self, tag, status=None, words=()):
        Exception.__init__(self)
        self.tag, self.status, self.words = tag, status, tuple(words)


def chain_reaches(agents, start, signer):
    """Follow the agent map from `start`: a stop at the signer passes, a missing key fails."""
    key = start
    while key in agents:
        key = agents[key]
        if key == signer:
            return True
    return False


def asset_gate(case, asset, events, prior=None, listed=False):
    """One classified asset; returns the encoded id or raises the refusal.

    The list arm reads its refusal word before writing this asset to that slot, so kind 1 reports the id of the asset before it."""
    events.append(("classify", asset))
    status, kind, encoded = case.get("classify", {}).get(asset, (OK, 0, asset))
    if status != OK:
        raise Result(RESULT_ERROR, status, (kind, encoded))
    if kind == 1:
        raise Result(RESULT_ERROR, WRONG_KIND, ((prior,) if prior is not None else ()) if listed else (encoded,))
    dexes = case.get("dexes", (MAIN,))
    dex = encoded // DEX_STEP
    if dex >= len(dexes):
        raise Panicked("unwrap")
    if dexes[dex] != MAIN:
        raise Result(RESULT_ERROR, NOT_MAIN, (encoded,))
    return encoded


def action_spec(case):
    events = []
    frees = []
    signer, default = case["signer"], case["default"]
    agents = case.get("agents", {})
    entries = case.get("entries", ())
    flag, asset = 0, None
    routes = {}
    try:
        if default not in case.get("liquidators", ()):
            raise Result(RESULT_ERROR, NO_LIQUIDATOR)
        if signer != default:
            if default not in agents:
                raise Result(RESULT_ERROR, NO_LIQUIDATOR)
            if not chain_reaches(agents, default, signer):
                raise Result(RESULT_ERROR, NOT_AGENT, (signer, default))
        mode = case.get("mode", "none")
        if mode == "single":
            asset = asset_gate(case, case["asset"], events)
            flag = 1
        elif mode == "list":
            words = case.get("map_len", len(entries))
            if words > LIST_LIMIT:
                events.append(("drop map",))
                raise Result(RESULT_ERROR, TOO_MANY, ("map",))
            seen = 0
            prior, span = None, None
            for index, (key, assets, *rest) in enumerate(sorted(entries)):
                if seen == words:
                    break
                seen += 1
                length = rest[0] if rest else len(assets)
                if length > LIST_LIMIT:
                    events += [("drop set",), ("drop map",)]
                    raise Result(RESULT_ERROR, TOO_MANY, ("value", span))
                span = index
                if not assets:
                    length = 0
                if length > len(assets):
                    raise Panicked("none")
                found = set()
                try:
                    for item in sorted(assets)[:length]:
                        prior = asset_gate(case, item, events, prior, True)
                        found.add(prior)
                except Result:
                    events += [("drop set",), ("drop map",)]
                    raise
                if key not in case.get("liquidators", ()):
                    events += [("drop set",), ("drop map",)]
                    raise Result(RESULT_ERROR, NO_LIQUIDATOR)
                if key != signer:
                    if key not in agents:
                        events += [("drop set",), ("drop map",)]
                        raise Result(RESULT_ERROR, NO_LIQUIDATOR)
                    if not chain_reaches(agents, key, signer):
                        events += [("drop set",), ("drop map",)]
                        raise Result(RESULT_ERROR, NOT_AGENT, (signer, key))
                routes[key] = found
            if words > seen:
                raise Panicked("none")
        if default in routes:
            events.append(("drop iter",))
            raise Result(RESULT_ERROR, DEFAULT_LISTED)
        owners = {}
        for place, key in enumerate(sorted(routes)):
            for item in sorted(routes[key]):
                if item in owners:
                    events.append(("drop iter",))
                    events.append(("drop assets",))
                    frees.append(grown(place + 2) * 20)
                    raise Result(RESULT_ERROR, DUPLICATE, (item,))
                owners[item] = key
        order = [default] + sorted(routes)
        events.append(("drop iter",))
        events.append(("run", case["user"], flag, asset if flag else None, tuple(order), tuple(sorted(owners.items())), default))
        failed = case.get("run_error")
        if failed is not None:
            events.append(("drop route",))
            frees.append(grown(len(order)) * 20)
            raise Result(RESULT_ERROR, failed)
        events.append(("drop route",))
        frees.append(grown(len(order)) * 20)
        return dict(tag=RESULT_OK, status=None, words=(0x71, 0x72, 0x73), events=events, frees=frees)
    except Result as stop:
        return dict(tag=stop.tag, status=stop.status, words=stop.words, events=events, frees=frees)


def grown(count):
    """Capacity of a vector after `count` pushes from one."""
    cap = 1
    while cap < count:
        cap = max(cap * 2, 4)
    return cap


def saturate(value):
    if value != value or value in (float("inf"), float("-inf")):
        return 0
    if value >= 2.0 ** 63:
        return I64_MAX
    if value <= -(2.0 ** 63):
        return I64_MIN
    return int(value)


def limit_price(size, value, total, amount):
    """Price of a position hand-over, and whether the checked subtraction logged."""
    share = float(abs(value)) / float(total) if total else 0.0
    taken = saturate(float(amount) * share)
    rest = value - taken
    logged = 0
    if rest > I64_MAX or rest < I64_MIN:
        logged = 1
        rest = I64_MAX if rest > 0 else I64_MIN
    rest = max(rest, 1) if size > 0 else min(rest, -1)
    whole, count = abs(rest), abs(size)
    return (whole // count if whole > count - 1 else 1), logged


def cancel_ids(case):
    """Asset ids whose user orders are cancelled by the whole-dex path."""
    dex_id = case.get("dex_id", 0)
    start = dex_id * DEX_STEP
    if start >> 64:
        raise Panicked("mul")
    held = case.get("positions", {})
    ids = []
    for index in range(len(case.get("markets", ()))):
        at = start + index
        if at >> 64:
            raise Panicked("add")
        row = held.get(at)
        if row is not None and row[0] != 0 and row[1] != 0:
            continue
        ids.append((at, row is None))
    return ids


def run_spec(case):
    events, frees = [], []
    logs = 0
    dex = case.get("dex", 0)
    dexes = case.get("dex_count", 1)
    if dex >= dexes:
        raise Panicked("unwrap")
    events.append(("plan", case["user"], case.get("flag", 0), case.get("asset", 0) if case.get("flag") else None))
    failed = case.get("plan_error")
    if failed is not None:
        return dict(status=failed, words=(), events=events, frees=frees, logs=0, counter=case.get("counter", 100))
    rows = case.get("rows", ())
    if case.get("no_root"):
        raise Panicked("none")
    if not case.get("no_map"):
        events.append(("clone map",))
    counter = case.get("counter", 100)
    once = bool(case.get("once"))
    for at, row in enumerate(rows):
        events.append(("items", len(row["items"])))
        events.append(("event", case["user"], "Isolated" if row.get("tag", 0) == 1 else "Cross", float(row["total"]) / 1e6, float(row["amount"]) / 1e6, 0x6201 + at))
    if case.get("flag"):
        asset = case.get("asset", 0)
        dex_at = asset // DEX_STEP
        if dex_at >= case.get("book_tables", 8):
            raise Panicked("unwrap")
        local = asset % DEX_STEP
        if local >= case.get("books", 4):
            raise Panicked("none")
        events.append(("cancel", dex_at, local))
        events.append(("flush", dex_at))
    else:
        events.append(("user",))
        if case.get("positions"):
            events.append(("clone positions",))
        for at, missing in cancel_ids(case):
            if missing:
                events.append(("decode", at))
            dex_at, local = at // DEX_STEP, at % DEX_STEP
            if dex_at >= case.get("book_tables", 8):
                raise Panicked("unwrap")
            if local >= case.get("books", 4):
                raise Panicked("none")
            events.append(("cancel", dex_at, local))
            events.append(("flush", dex_at))
        events.append(("drop positions",))
    words = [row.get("ident", 0) for row in rows]
    for at, row in enumerate(rows):
        if row.get("tag", 0) == 2:
            for later in rows[at + 1:]:
                if later.get("cap", len(later["items"])):
                    frees.append(later.get("cap", len(later["items"])) * ITEM_STRIDE)
            break
        ids = []
        for _ in row["items"]:
            ids.append(counter)
            counter = min(counter + 1, MASK[8])
        if once:
            once = False
            events.append(("once",))
        for index, (asset, size, value) in enumerate(row["items"]):
            if size == 0:
                continue
            if size == I64_MIN or value == I64_MIN:
                raise Halt("spec fixture")
            price, logged = limit_price(size, value, row["total"], row["amount"])
            logs += logged
            whole = price * abs(size)
            buy = int(size < 0)
            events.append(("order", asset, size, buy, index, tuple(ids)))
            if whole >= I64_MAX or whole >> 64 or case.get("order_tag") == 2:
                raise Panicked("none")
            kind = 1 if row.get("tag", 0) == 0 else 2
            events.append(("send", case.get("order_tag", 0), price, asset, abs(size), whole, buy, kind | buy << 8 | kind << 16 | buy << 24))
            events.append(("flush", dex))
        if ids:
            frees.append(len(ids) * 8)
        if row.get("cap", len(row["items"])):
            frees.append(row.get("cap", len(row["items"])) * ITEM_STRIDE)
    if case.get("rows_cap", len(rows)):
        frees.append(case.get("rows_cap", len(rows)) * ROW_STRIDE)
    events.append(("drop info",))
    return dict(status=OK, words=(len(words), tuple(words)), events=events, frees=frees, logs=logs, counter=counter)


# ---- harness ----

ADDRESS_SET = dict(leaf=0xE8, inner=0x148, parent=0, slot=0xE4, length=0xE6, keys=8, stride=20, edges=0xE8, values=0)
AGENT_MAP = dict(leaf=0x878, inner=0x8D8, parent=0x790, slot=0x874, length=0x876, keys=0x798, stride=20, edges=0x878, values=0xB0, value_base=0x98)
ACTION_MAP = dict(leaf=0x1F0, inner=0x250, parent=0, slot=0x1EC, length=0x1EE, keys=0x110, stride=20, edges=0x1F0, values=24, value_base=8)
ASSET_SET = dict(leaf=0x38, inner=0x98, parent=0, slot=0x34, length=0x36, keys=8, stride=4, edges=0x38, values=0)
POSITION_MAP = dict(leaf=0x328, inner=0x388, parent=0x2C0, slot=0x320, length=0x322, keys=0x2C8, stride=8, edges=0x328, values=0x40)
ROUTE_MAP = dict(leaf=0x140, inner=0x1A0, parent=0, slot=0x13C, length=0x13E, keys=8, stride=8, edges=0x140, values=20, value_base=0x60)
CAPACITY = 11
TREE_HELPERS = (0x1A9BC20, 0x2F32F40, 0x1AE9AE0, 0x41E7500, 0x4212E10)


def tree_height(count):
    level, room = 0, CAPACITY
    while room < count:
        level += 1
        room = room * (CAPACITY + 1) + CAPACITY
    return level


def build_tree(memory, bump, shape, items, put):
    """B-tree over sorted (key bytes, value) items; returns the root and its height."""
    if not items:
        return 0, 0
    base = shape.get("value_base", 0)

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
            memory.put_bytes(node + shape["keys"] + shape["stride"] * index, key)
            put(node + base + shape["values"] * index, value)
        for index, part in enumerate(children):
            memory.write(node + shape["edges"] + 8 * index, 8, make(part, level - 1, node, index))
        return node

    height = tree_height(len(items))
    return make(items, height, 0, 0), height


def tree_items(memory, shape, node, height):
    """(key bytes, value address) in key order."""
    if not node:
        return []
    found = []
    count = memory.read(node + shape["length"], 2)
    for index in range(count + 1):
        if height:
            found += tree_items(memory, shape, memory.read(node + shape["edges"] + 8 * index, 8), height - 1)
        if index < count:
            found.append((memory.bytes_at(node + shape["keys"] + shape["stride"] * index, shape["stride"]), node + shape.get("value_base", 0) + shape["values"] * index))
    return found


def word_key(value):
    return struct.pack("<Q", value)


def nothing(at, value):
    return None


class Harness:
    def __init__(self, image):
        self.image = image
        machine = self.machine = Machine(image)
        real = {ROUTE, EVENT_ROW, ITER_MAP, ITER_SET, ROUTE_INSERT} | set(TREE_HELPERS)
        for layout in COPIES:
            real.update((layout["entry"], layout["run"], layout["set_insert"], layout["member"], layout["agent_get"], layout["chain"], layout["map_insert"], layout["clone_rows"]))
        machine.real = frozenset(real)
        machine.jump_ranges = [image.exact_fde(start) for start in real]
        self.tree_ranges = [image.exact_fde(start) for start in (ROUTE_INSERT,) + TREE_HELPERS] + [image.exact_fde(layout[name]) for layout in COPIES for name in ("set_insert", "map_insert")]
        machine.calls = {STATUS_DROP: self.on_status, DECODE: self.on_decode, BLOCK: self.on_block, ITEMS: self.on_items, DROP_ITER: self.on_drop_iter, DROP_ASSETS: self.on_drop_assets}
        for layout in COPIES:
            machine.calls.update({layout["drop_set"]: self.on_drop_set, layout["drop_route"]: self.on_drop_route, layout["drop_map"]: self.on_drop_map, layout["clone_map"]: self.on_clone_map, layout["cancel"]: self.on_cancel,
                                  layout["flush"]: self.on_flush, layout["clone_positions"]: self.on_clone_positions, layout["drop_positions"]: self.on_drop_positions, layout["drop_info"]: self.on_drop_info,
                                  layout["order"]: self.on_order, layout["send"]: self.on_send, layout["sink"]: self.on_event})
        hooks = {CLASSIFY: self.on_classify, PLAN: self.on_plan, USER_STATE: self.on_user, GROW_USERS: self.on_grow(20), OVERFLOW_LOG: self.on_log, ONCE_CALL: self.on_once,
                 PANIC_NONE: self.on_panic("none"), PANIC_UNWRAP: self.on_panic("unwrap"), PANIC_ADD: self.on_panic("add"), PANIC_MUL: self.on_panic("mul")}
        machine.calls[USER_STATE] = self.on_user
        machine.calls[STATUS_DROP] = self.on_status
        tokens = {}
        for at, (target, hook) in enumerate(hooks.items()):
            token = 0x7000000 + at * 16
            tokens[target] = token
            machine.slots[token] = hook
        slots = relative_slots(image)
        for slot, target in slots.items():
            if target in tokens:
                machine.memory.statics[slot] = tokens[target]
            elif target in real:
                machine.memory.statics[slot] = target
            elif target in machine.calls:
                token = 0x7200000 + target
                machine.slots[token] = machine.calls[target]
                machine.memory.statics[slot] = token
        for at, (slot, hook) in enumerate(((SLOT_ALLOC, self.on_alloc), (SLOT_FREE, self.on_free), (SLOT_MEMCMP, self.on_memcmp), (SLOT_MEMCPY, self.on_memcpy))):
            token = 0x7100000 + at * 16
            machine.memory.statics[slot] = token
            machine.slots[token] = hook
        self.case = None
        self.at = BUMP
        self.events, self.frees = [], []
        self.logs = 0
        self.nodes = set()
        self.layout = COPIES[0]
        self.vector = 0
        self.expect_user = None
        self.dex_row = 0
        self.items_seen = 0
        self.order_seen = None
        self.row_data = 0

    def bump(self, size):
        here = self.at
        self.at += (size + 15) & ~15
        if self.at >= HEAP_BASE + HEAP_SIZE:
            raise Halt("heap exhausted")
        return here

    def node(self, size):
        at = self.bump(size)
        self.nodes.add(at)
        return at

    # edge hooks

    def on_alloc(self, machine):
        at = self.bump(machine.regs[RDI])
        if any(low <= machine.call_site < high for low, high in self.tree_ranges):
            self.nodes.add(at)
        machine.regs[RAX] = at

    def on_free(self, machine):
        if machine.regs[RDI] in self.nodes:
            self.nodes.discard(machine.regs[RDI])
        else:
            self.frees.append(machine.regs[RSI])

    def on_memcmp(self, machine):
        regs, memory = machine.regs, machine.memory
        left = memory.bytes_at(regs[RDI], regs[RDX])
        right = memory.bytes_at(regs[RSI], regs[RDX])
        regs[RAX] = 0 if left == right else (1 if left > right else MASK[4])

    def on_memcpy(self, machine):
        regs = machine.regs
        if regs[RDX]:
            machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def on_log(self, machine):
        self.logs += 1

    def on_panic(self, name):
        def panic(machine):
            raise Panicked(name)
        return panic

    def on_once(self, machine):
        regs = machine.regs
        if regs[RDI] != ONCE_WORD or regs[RSI] & 0xFF != 1:
            raise Halt("once arguments")
        machine.memory.statics[regs[RDI]] = 0
        self.events.append(("once",))

    def on_grow(self, size):
        def grow(machine):
            regs, memory = machine.regs, machine.memory
            vector = regs[RDI]
            cap, data = memory.read(vector, 8), memory.read(vector + 8, 8)
            wider = max(cap * 2, 4)
            fresh = self.bump(wider * size)
            if cap:
                memory.copy(fresh, data, cap * size)
            memory.write(vector, 8, wider)
            memory.write(vector + 8, 8, fresh)
        return grow

    def on_status(self, machine):
        if machine.memory.read(machine.regs[RDI], 2) != 0x141:
            raise Halt("status drop")

    def on_classify(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDX] != EXCHANGE + 0x5B8 + self.shift or regs[RCX] != EXCHANGE + 0x90:
            raise Halt("classify arguments")
        asset = regs[RSI] & MASK[4]
        self.events.append(("classify", asset))
        status, kind, encoded = self.case.get("classify", {}).get(asset, (OK, 0, asset))
        out = regs[RDI]
        memory.write(out, 2, status)
        memory.write(out + 8, 8, kind)
        memory.write(out + 0x10, 8, encoded)
        if status != OK:
            memory.put_bytes(out + 0x18, bytes((index * 5 + 7) & 0xFF for index in range(0x48)))
            memory.put_bytes(out + 2, b"\x21\x22\x23\x24\x25\x26")
            self.error_body = memory.bytes_at(out + 2, 0x5E)

    def on_drop_set(self, machine):
        self.events.append(("drop set",))

    def on_drop_map(self, machine):
        self.events.append(("drop map",))

    def on_drop_route(self, machine):
        self.events.append(("drop route",))

    def on_drop_iter(self, machine):
        self.events.append(("drop iter",))

    def on_drop_assets(self, machine):
        self.events.append(("drop assets",))

    def route_view(self, route):
        memory = self.machine.memory
        cap, data, count = memory.read(route, 8), memory.read(route + 8, 8), memory.read(route + 16, 8)
        order = tuple(memory.bytes_at(data + 20 * index, 20) for index in range(count))
        owners = tuple((struct.unpack("<Q", key)[0], memory.bytes_at(at, 20)) for key, at in tree_items(memory, ROUTE_MAP, memory.read(route + 0x18, 8), memory.read(route + 0x20, 8)))
        return cap, order, owners, memory.bytes_at(route + 0x30, 20)

    def on_run(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] != EXCHANGE or regs[RCX] != 0:
            raise Halt("run arguments")
        route = memory.read(regs[RSP] + 8, 8)
        flag = regs[R8]
        _, order, owners, default = self.route_view(route)
        self.events.append(("run", memory.bytes_at(regs[RDX], 20), flag, regs[R9] if flag else None, order, owners, default))
        out = regs[RDI]
        failed = self.case.get("run_error")
        if failed is not None:
            memory.write(out, 2, failed)
            memory.put_bytes(out + 2, bytes((index * 5 + 7) & 0xFF for index in range(0x5E)))
            self.error_body = memory.bytes_at(out + 2, 0x5E)
            return
        memory.write(out, 2, OK)
        memory.write(out + 8, 8, 0x71)
        memory.write(out + 0x10, 8, 0x72)
        memory.write(out + 0x18, 8, 0x73)

    def on_plan(self, machine):
        regs, memory = machine.regs, machine.memory
        case = self.case
        if regs[RSI] != self.dex_row or regs[R9] != self.route_at or memory.read(regs[RSP], 8) != EXCHANGE:
            raise Halt("plan arguments")
        if regs[RCX] != case.get("flag", 0) or regs[R8] != self.expect_asset:
            raise Halt("plan flag")
        self.events.append(("plan", memory.bytes_at(regs[RDX], 20), case.get("flag", 0), regs[R8] if case.get("flag") else None))
        out = regs[RDI]
        failed = case.get("plan_error")
        if failed is not None:
            memory.write(out, 2, failed)
            for index in range(0x5E):
                memory.write(out + 2 + index, 1, index + 1)
            return
        rows = case.get("rows", ())
        cap = case.get("rows_cap", len(rows))
        data = self.bump(max(cap, 1) * ROW_STRIDE)
        self.row_data = data
        for index, row in enumerate(rows):
            at = data + index * ROW_STRIDE
            items = self.bump(max(len(row["items"]), 1) * ITEM_STRIDE)
            for place, (asset, size, value) in enumerate(row["items"]):
                memory.write(items + place * ITEM_STRIDE, 8, asset)
                memory.write(items + place * ITEM_STRIDE + 8, 8, word_of(size))
                memory.write(items + place * ITEM_STRIDE + 16, 8, word_of(value))
            memory.write(at, 8, row.get("tag", 0))
            memory.write(at + 8, 8, 0x3030)
            memory.write(at + 0x10, 8, row.get("cap", len(row["items"])))
            memory.write(at + 0x18, 8, items)
            memory.write(at + 0x20, 8, len(row["items"]))
            memory.write(at + 0x28, 8, row.get("ident", 0))
            memory.write(at + 0x30, 8, row["total"])
            memory.write(at + 0x38, 8, word_of(row["amount"]))
            memory.put_bytes(at + 0x40, row.get("first", address(0x41, 0xC1)))
            memory.put_bytes(at + 0x54, row.get("second", address(0x42, 0xC2)))
        memory.write(out, 2, OK)
        memory.write(out + 8, 8, cap)
        memory.write(out + 0x10, 8, data)
        memory.write(out + 0x18, 8, len(rows))

    def on_clone_map(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] != 0xABC0 or regs[RDX] != 0xABC1:
            raise Halt("clone map arguments")
        if self.case.get("no_root"):
            raise Halt("clone map on an empty root")
        self.events.append(("clone map",))
        memory.write(regs[RDI], 8, 0x9001)
        memory.write(regs[RDI] + 8, 8, 0x9002)
        memory.write(regs[RDI] + 16, 8, 0x9003)

    def on_items(self, machine):
        regs, memory = machine.regs, machine.memory
        source, out = regs[RSI], regs[RDI]
        row = self.case["rows"][self.items_seen]
        begin, end, context = memory.read(source, 8), memory.read(source + 8, 8), memory.read(source + 0x10, 8)
        if (end - begin) // ITEM_STRIDE != len(row["items"]) or memory.read(begin if row["items"] else 0x0 + begin, 8) != (row["items"][0][0] if row["items"] else memory.read(begin, 8)):
            raise Halt("items arguments")
        self.check_context(context)
        self.events.append(("items", len(row["items"])))
        self.items_seen += 1
        memory.write(out, 8, 0x61)
        memory.write(out + 8, 8, 0x6200 + self.items_seen)
        memory.write(out + 16, 8, 0x63)

    def check_context(self, context):
        """The dex clone handed to the event rows: market list, dex name, id, map, two trailing fields."""
        memory, case = self.machine.memory, self.case
        markets = case.get("markets", ())
        data = memory.read(context + 8, 8)
        if memory.read(context, 8) != len(markets) or memory.read(context + 0x10, 8) != len(markets):
            raise Halt("context list")
        for index, name in enumerate(markets):
            at = data + index * 0x30
            if memory.read(at, 8) != len(name) or memory.read(at + 0x10, 8) != len(name) or name and memory.bytes_at(memory.read(at + 8, 8), len(name)) != name:
                raise Halt("context market name")
            if (memory.read(at + 0x18, 8), memory.read(at + 0x20, 8), memory.read(at + 0x28, 2), memory.read(at + 0x2A, 1)) != (0x1111 + index, 0x2222 + index, 0x3333, 0x44):
                raise Halt("context market fields")
        name = case.get("dex_name", b"dexname")
        if memory.read(context + 0x18, 8) != len(name) or memory.read(context + 0x28, 8) != len(name) or name and memory.bytes_at(memory.read(context + 0x20, 8), len(name)) != name:
            raise Halt("context name")
        if memory.read(context + 0x30, 8) != case.get("dex_id", 0):
            raise Halt("context id")
        want = [0, 0, 0] if case.get("no_map") else [0x9001, 0x9002, 0x9003]
        if want[0] and [memory.read(context + at, 8) for at in (0x38, 0x40, 0x48)] != want or not want[0] and memory.read(context + 0x38, 8) | memory.read(context + 0x48, 8):
            raise Halt("context map")
        if memory.read(context + 0x50, 8) != 0x5050 or memory.read(context + 0x58, 1) != 0x58:
            raise Halt("context tail")

    def on_block(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] & 0xFF != 0x5D or regs[RDX] != 0x2828 or regs[RCX] != 0x0808 or regs[R8] & 0xFF:
            raise Halt("block arguments")
        memory.put_bytes(regs[RDI], bytes(range(0xA0, 0xC0)))

    def on_event(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != EXCHANGE + (0x5B8 if self.shift else 0x8F3):
            raise Halt("sink")
        users = regs[RSI]
        if memory.read(users, 8) != 1 or memory.read(users + 16, 8) != 1:
            raise Halt("sink users")
        if memory.bytes_at(regs[RDX], 12) != BLOCK_TIME:
            raise Halt("sink time")
        want = bytes(range(0xA0, 0xC0)) if self.case.get("block") else bytes(32)
        if memory.bytes_at(regs[RCX], 32) != want:
            raise Halt("sink block")
        row = regs[R8]
        if memory.read(row, 8) != 0x800000000000000A:
            raise Halt("event tag")
        size = memory.read(row + 8, 8)
        if size != memory.read(row + 0x18, 8):
            raise Halt("event name length")
        name = memory.bytes_at(memory.read(row + 0x10, 8), size).decode("ascii")
        self.events.append(("event", memory.bytes_at(memory.read(users + 8, 8), 20), name, to_float(memory.read(row + 0x38, 8)), to_float(memory.read(row + 0x40, 8)), memory.read(row + 0x28, 8)))

    def on_user(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDI] != self.dex_row + 0xF8:
            raise Halt("user arguments")
        self.events.append(("user",))
        if memory.bytes_at(regs[RSI], 20) != self.case["user"]:
            raise Halt("user key")
        block = self.bump(0x40)
        positions = self.case.get("positions", {})
        memory.write(block + 8, 8, 0xBEEF if positions else 0)
        memory.write(block + 0x10, 8, 0xBEE0)
        memory.write(block + 0x18, 8, len(positions))
        memory.write(block + 0x20, 8, 0x7777)
        regs[RAX] = block

    def on_clone_positions(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RSI] != 0xBEEF or regs[RDX] != 0xBEE0:
            raise Halt("clone positions arguments")
        self.events.append(("clone positions",))
        positions = self.case["positions"]

        def put(at, value):
            memory.write(at, 4, value[0])
            memory.write(at + 0x10, 8, value[1])
        root, height = build_tree(memory, self.bump, POSITION_MAP, [(word_key(key), positions[key]) for key in sorted(positions)], put)
        memory.write(regs[RDI], 8, root)
        memory.write(regs[RDI] + 8, 8, height)
        memory.write(regs[RDI] + 16, 8, len(positions))

    def on_drop_positions(self, machine):
        memory = self.machine.memory
        at = machine.regs[RDI]
        if memory.read(at + 0x18, 8) != 0x7777 or memory.read(at + 0x10, 8) != len(self.case.get("positions", {})):
            raise Halt("drop positions argument")
        if not self.case.get("positions") and memory.read(at, 8):
            raise Halt("drop positions root")
        self.events.append(("drop positions",))

    def on_decode(self, machine):
        regs, memory = machine.regs, machine.memory
        self.events.append(("decode", regs[RSI]))
        if memory.read(regs[RDX] + 0x30, 8) != self.case.get("dex_id", 0):
            raise Halt("decode context")
        memory.write(regs[RDI], 8, POISON)

    def on_cancel(self, machine):
        regs, memory = machine.regs, machine.memory
        if memory.bytes_at(regs[RSI], 20) != self.case["user"]:
            raise Halt("cancel user")
        if self.layout["name"] == "primary":
            exchange, acc, reason = regs[RDX], regs[RCX], regs[R8]
        else:
            if regs[RDX] != 1:
                raise Halt("cancel mark")
            exchange, acc, reason = regs[RCX], regs[R8], regs[R9]
        if exchange != EXCHANGE or reason & MASK[4] != CANCEL_REASON:
            raise Halt("cancel arguments")
        table = memory.read(EXCHANGE + 0x3370 + self.shift, 8)
        found = None
        for dex in range(memory.read(EXCHANGE + 0x3378 + self.shift, 8)):
            base = memory.read(table + dex * 0x138 + 8, 8)
            for local in range(memory.read(table + dex * 0x138 + 0x10, 8)):
                if regs[RDI] == base + local * 0xD8:
                    found = (dex, local)
        if found is None:
            raise Halt("cancel book")
        if [memory.read(acc + 8 * index, 8) for index in range(3)] != [0, 8, 0]:
            raise Halt("cancel accumulator")
        self.events.append(("cancel",) + found)
        memory.write(acc, 8, 0x51)
        memory.write(acc + 8, 8, 0x52)
        memory.write(acc + 16, 8, 0x53)
        self.closure = table + found[0] * 0x138 if self.layout["name"] == "primary" else None

    def on_flush(self, machine):
        regs, memory = machine.regs, machine.memory
        if regs[RDX] != EXCHANGE or [memory.read(regs[RDI] + at, 8) for at in (0, 8, 16)] != [0x51, 0x52, 0x53]:
            raise Halt("flush arguments")
        if self.closure is not None:
            if [memory.read(regs[RDI] + at, 8) for at in (0x18, 0x20, 0x28)] != [self.closure + 0x18, self.closure, EXCHANGE]:
                raise Halt("flush closure")
            self.closure = None
        self.events.append(("flush", regs[RSI]))

    def on_order(self, machine):
        regs, memory = machine.regs, machine.memory
        context = regs[RSI]
        words = [memory.read(context + 8 * index, 8) for index in range(8)]
        buy = memory.read(words[0], 1)
        row = self.case["rows"][self.current_row(words)]
        if memory.bytes_at(words[1], 20) != row.get("first", address(0x41, 0xC1)) or memory.bytes_at(words[2], 20) != row.get("second", address(0x42, 0xC2)):
            raise Halt("order parties")
        size = signed(memory.read(words[3], 8))
        if words[4] != self.dex_row:
            raise Halt("order dex row")
        asset = memory.read(words[5], 8)
        vector = words[6]
        data, count = memory.read(vector + 8, 8), memory.read(vector + 16, 8)
        ids = tuple(memory.read(data + 8 * index, 8) for index in range(count))
        index = memory.read(words[7], 8)
        self.events.append(("order", asset, size, buy, index, ids))
        out = regs[RDI]
        memory.write(out, 8, self.case.get("order_tag", 0))
        memory.put_bytes(out + 8, bytes((index * 3 + 1) & 0xFF for index in range(0x1F8)))

    def current_row(self, words):
        return self.row_cursor()

    def row_cursor(self):
        """Row of the running order, from the iterator word the executor keeps at rsp +0x108."""
        memory = self.machine.memory
        return (memory.read(self.machine.regs[RSP] + 8 + 0x108, 8) - self.row_data) // ROW_STRIDE - 1

    def on_send(self, machine):
        regs, memory = machine.regs, machine.memory
        if self.layout["name"] == "primary":
            first, second, row, one, source, zero, mode, vector = regs[RDI], regs[RSI], regs[RDX], regs[RCX], regs[R8], regs[R9], memory.read(regs[RSP] + 8, 8), memory.read(regs[RSP] + 16, 8)
        else:
            if regs[RDI] != self.dex_row:
                raise Halt("send view")
            first, second, row, one, source, zero, mode, vector = 0x6868, 0x7070, regs[RSI], regs[RDX], regs[RCX], regs[R8], regs[R9], memory.read(regs[RSP] + 8, 8)
        if first != 0x6868 or second != 0x7070 or one != 1 or zero & 0xFF:
            raise Halt("send arguments")
        if memory.bytes_at(row + 8, 0x1F8) != bytes((index * 3 + 1) & 0xFF for index in range(0x1F8)):
            raise Halt("send order body")
        if memory.bytes_at(row + 0x228, 12) != BLOCK_TIME:
            raise Halt("send time")
        want = b"\x01" + (bytes(range(0xA0, 0xC0)) if self.case.get("block") else bytes(32))
        if memory.bytes_at(source, 33) != want:
            raise Halt("send source")
        if memory.read(row + 0x220, 8):
            raise Halt("send zero word")
        if [memory.read(vector + at, 8) for at in (0, 8, 16)] != [0, 8, 0]:
            raise Halt("send vector")
        self.events.append(("send", memory.read(row, 8), memory.read(row + 0x200, 8), memory.read(row + 0x208, 8), memory.read(row + 0x210, 8), memory.read(row + 0x218, 8), memory.read(row + 0x234, 1), mode & MASK[4]))
        memory.write(vector, 8, 0x51)
        memory.write(vector + 8, 8, 0x52)
        memory.write(vector + 16, 8, 0x53)

    def on_drop_info(self, machine):
        self.events.append(("drop info",))

    # fixtures

    def begin(self, case):
        memory = self.machine.memory
        memory.reset()
        self.case = case
        self.at = BUMP
        self.events, self.frees = [], []
        self.logs = 0
        self.nodes = set()
        self.layout = BY_NAME[case.get("copy", "primary")]
        self.shift = 0xA80 if self.layout["name"] == "recording" else 0
        self.items_seen = 0
        self.closure = None
        self.error_body = None
        memory.statics[ONCE_WORD] = 1 if case.get("once") else 0

    def run_action(self, case):
        machine, memory = self.machine, self.machine.memory
        self.begin(case)
        machine.calls[self.layout["run"]] = self.on_run
        saved = machine.real
        machine.real = saved - {self.layout["run"]}
        try:
            return self.action_body(case)
        finally:
            machine.real = saved
            del machine.calls[self.layout["run"]]

    def action_body(self, case):
        machine, memory = self.machine, self.machine.memory
        root, height = build_tree(memory, self.node, ADDRESS_SET, [(key, key) for key in sorted(case.get("liquidators", ()))], nothing)
        memory.write(EXCHANGE + 0x3948 + self.shift, 8, root)
        memory.write(EXCHANGE + 0x3950 + self.shift, 8, height)
        agents = case.get("agents", {})

        def put_agent(at, key):
            memory.put_bytes(at, agents[key])
        root, height = build_tree(memory, self.node, AGENT_MAP, [(key, key) for key in sorted(agents)], put_agent)
        memory.write(EXCHANGE + 0x8D0 + self.shift, 8, root)
        memory.write(EXCHANGE + 0x8D8 + self.shift, 8, height)
        dexes = case.get("dexes", (MAIN,))
        table = self.bump(0x2F0 * len(dexes))
        for index, status in enumerate(dexes):
            memory.write(table + 0x2F0 * index + 0x230, 1, status)
        memory.write(EXCHANGE + 0x5C0 + self.shift, 8, table)
        memory.write(EXCHANGE + 0x5C8 + self.shift, 8, len(dexes))
        action = self.bump(0x48)
        memory.put_bytes(action + 0x20, case["user"])
        memory.put_bytes(action + 0x34, case["default"])
        mode = case.get("mode", "none")
        memory.write(action, 8, dict(none=0, single=2, list=1).get(mode, 0))
        if case.get("tag") is not None:
            memory.write(action, 8, case["tag"])
        if mode == "single":
            memory.write(action + 8, 4, case["asset"])
        if mode == "list":
            entries = sorted(case.get("entries", ()))

            def put_value(at, value):
                assets, length = value
                inner, level = build_tree(memory, self.node, ASSET_SET, [(struct.pack("<I", item), item) for item in sorted(assets)], nothing)
                memory.write(at, 8, inner)
                memory.write(at + 8, 8, level)
                memory.write(at + 16, 8, length)
            root, height = build_tree(memory, self.node, ACTION_MAP, [(entry[0], (entry[1], entry[2] if len(entry) > 2 else len(entry[1]))) for entry in entries], put_value)
            memory.write(action + 8, 8, root)
            memory.write(action + 0x10, 8, height)
            memory.write(action + 0x18, 8, case.get("map_len", len(entries)))
        signer = self.bump(20)
        memory.put_bytes(signer, case["signer"])
        out = self.bump(0x70)
        self.action_at = action
        machine.run(self.layout["entry"], {RDI: out, RSI: action, RDX: signer, RCX: EXCHANGE})
        tag = memory.read(out, 1)
        return dict(tag=tag, out=out, status=memory.read(out + 8, 2) if tag == RESULT_ERROR else None)

    def run_exec(self, case):
        machine, memory = self.machine, self.machine.memory
        self.begin(case)
        dex = case.get("dex", 0)
        count = case.get("dex_count", 1)
        table = self.bump(0x2F0 * max(count, 1))
        memory.write(EXCHANGE + 0x5C0 + self.shift, 8, table)
        memory.write(EXCHANGE + 0x5C8 + self.shift, 8, count)
        row = self.dex_row = table + 0x2F0 * dex
        markets = case.get("markets", ())
        if dex < count:
            data = self.bump(max(len(markets), 1) * 0x30)
            for index, name in enumerate(markets):
                name_at = self.bump(max(len(name), 1))
                memory.put_bytes(name_at, name)
                at = data + index * 0x30
                memory.write(at, 8, len(name))
                memory.write(at + 8, 8, name_at)
                memory.write(at + 0x10, 8, len(name))
                memory.write(at + 0x18, 8, 0x1111 + index)
                memory.write(at + 0x20, 8, 0x2222 + index)
                memory.write(at + 0x28, 2, 0x3333)
                memory.write(at + 0x2A, 1, 0x44)
            memory.write(row + 8, 8, data)
            memory.write(row + 0x10, 8, len(markets))
            text = self.bump(16)
            name = case.get("dex_name", b"dexname")
            memory.put_bytes(text, name)
            memory.write(row + 0x20, 8, text)
            memory.write(row + 0x28, 8, len(name))
            memory.write(row + 0x30, 8, case.get("dex_id", 0))
            memory.write(row + 0x38, 8, 0 if case.get("no_root") else 0xABC0)
            memory.write(row + 0x40, 8, 0xABC1)
            memory.write(row + 0x48, 8, 0 if case.get("no_map") else 1)
            memory.write(row + 0x50, 8, 0x5050)
            memory.write(row + 0x58, 1, 0x58)
            memory.write(row + 0x68, 8, 0x6868)
            memory.write(row + 0x70, 8, 0x7070)
        memory.write(EXCHANGE, 4, 1 if case.get("block") else 0)
        memory.write(EXCHANGE + 8, 8, 0x0808)
        memory.write(EXCHANGE + 0x28, 8, 0x2828)
        memory.write(EXCHANGE + 0x8F2 + self.shift, 1, 0x5D)
        memory.put_bytes(EXCHANGE + 0x60, BLOCK_TIME)
        memory.write(EXCHANGE + 0x38, 8, case.get("counter", 100))
        tables = case.get("book_tables", 8)
        books = self.bump(0x138 * max(tables, 1))
        for index in range(tables):
            lines = self.bump(0xD8 * case.get("books", 4))
            memory.write(books + 0x138 * index + 8, 8, lines)
            memory.write(books + 0x138 * index + 0x10, 8, case.get("books", 4))
        memory.write(EXCHANGE + 0x3370 + self.shift, 8, books)
        memory.write(EXCHANGE + 0x3378 + self.shift, 8, tables)
        user = self.bump(20)
        memory.put_bytes(user, case["user"])
        self.expect_key = user
        self.expect_asset = case.get("asset", 0x5A5A)
        route = self.bump(0x50)
        for index in range(10):
            memory.write(route + index * 8, 8, 0xE000 + index)
        out = self.bump(0x70)
        sp_arg = route
        machine.memory.write(STACK_TOP - 0x100, 8, sp_arg)
        self.route_at = route
        machine.run(self.layout["run"], {RDI: out, RSI: EXCHANGE, RDX: user, RCX: dex, R8: case.get("flag", 0), R9: self.expect_asset})
        status = memory.read(out, 2)
        if status != OK:
            return dict(status=status, words=(), counter=memory.read(EXCHANGE + 0x38, 8), body=memory.bytes_at(out + 2, 0x5E))
        data, count = memory.read(out + 0x10, 8), memory.read(out + 0x18, 8)
        return dict(status=status, words=(memory.read(out + 8, 8), tuple(memory.read(data + 8 * index, 8) for index in range(count))), counter=memory.read(EXCHANGE + 0x38, 8))


def compare_run(harness, case):
    label = case["label"]
    kind = case["kind"]
    try:
        want = action_spec(case) if kind == "action" else run_spec(case)
    except Panicked as panic:
        want = dict(panic=str(panic))
    try:
        got = harness.run_action(case) if kind == "action" else harness.run_exec(case)
    except Panicked as panic:
        got = dict(panic=str(panic))
    except Halt as stop:
        return "%s: halt %s after %r" % (label, stop, harness.events[-3:])
    except (EvidenceError, KeyError, IndexError, ValueError, TypeError, struct.error, OverflowError, ZeroDivisionError) as error:
        return "%s: error %r" % (label, error)
    if "panic" in want or "panic" in got:
        if want.get("panic") != got.get("panic"):
            return "%s: panic %r against %r" % (label, want.get("panic"), got.get("panic"))
        return None if kind == "action" or "panic" in want else "%s: panic" % label
    if harness.events != want["events"]:
        for at in range(max(len(harness.events), len(want["events"]))):
            left = harness.events[at] if at < len(harness.events) else None
            right = want["events"][at] if at < len(want["events"]) else None
            if left != right:
                return "%s: event %d got %r want %r" % (label, at, left, right)
    if sorted(harness.frees) != sorted(want["frees"]):
        return "%s: frees got %r want %r" % (label, sorted(harness.frees), sorted(want["frees"]))
    if kind == "action":
        return action_outcome(harness, case, want, got)
    if got["status"] != want["status"]:
        return "%s: status got %#x want %#x" % (label, got["status"], want["status"])
    if got["status"] != OK:
        if got["body"] != bytes(index + 1 for index in range(0x5E)):
            return "%s: status body" % label
    elif got["words"] != want["words"]:
        return "%s: words got %r want %r" % (label, got["words"], want["words"])
    if got["counter"] != want["counter"]:
        return "%s: counter got %d want %d" % (label, got["counter"], want["counter"])
    if harness.logs != want["logs"]:
        return "%s: logs got %d want %d" % (label, harness.logs, want["logs"])
    return None


def action_outcome(harness, case, want, got):
    label = case["label"]
    memory = harness.machine.memory
    out = got["out"]
    if got["tag"] != want["tag"]:
        return "%s: tag got %#x want %#x" % (label, got["tag"], want["tag"])
    if want["tag"] == RESULT_OK:
        if [memory.read(out + at, 8) for at in (8, 0x10, 0x18)] != list(want["words"]):
            return "%s: result words" % label
        return None
    if got["status"] != want["status"]:
        return "%s: status got %#x want %#x" % (label, got["status"], want["status"])
    status, words = want["status"], want["words"]
    if harness.error_body is not None and memory.bytes_at(out + 0xA, 0x5E) != harness.error_body:
        return "%s: error row" % label
    if status == NOT_AGENT:
        if memory.bytes_at(out + 0xA, 20) != words[0] or memory.bytes_at(out + 0x1E, 20) != words[1]:
            return "%s: agent refusal addresses" % label
    elif status in (WRONG_KIND, NOT_MAIN):
        if words and memory.read(out + 0x10, 8) != words[0]:
            return "%s: refusal id" % label
    elif status == DUPLICATE:
        if memory.read(out + 0x10, 8) != words[0]:
            return "%s: duplicate id" % label
    elif status == TOO_MANY:
        want_at = harness.action_at + 8 if words[0] == "map" else None
        if want_at and memory.read(out + 0x10, 8) != want_at:
            return "%s: limit pointer" % label
        if not want_at and words[1] is not None:
            at = dict(tree_items(memory, ACTION_MAP, memory.read(harness.action_at + 8, 8), memory.read(harness.action_at + 0x10, 8)))
            rows = sorted(case["entries"])
            if memory.read(out + 0x10, 8) != at[rows[words[1]][0]]:
                return "%s: limit value pointer" % label
    elif status not in (NO_LIQUIDATOR, DEFAULT_LISTED):
        if len(words) == 2 and (memory.read(out + 0x10, 8) != words[0] or memory.read(out + 0x18, 8) != words[1]):
            return "%s: classify words" % label
    return None


# ---- cases ----

SIGNER = address(0x10)
BOSS = address(0x20)
LIQ = address(0x30)
HELP = address(0x40)
OTHER = address(0x50)
USER = address(0x60)


def act(label, **fields):
    case = dict(label=label, kind="action", signer=BOSS, default=BOSS, user=USER, liquidators=(BOSS,))
    case.update(fields)
    return case


def pair(label, **fields):
    return act(label, signer=SIGNER, agents={BOSS: SIGNER}, **fields)


def action_cases():
    many = tuple(address(index + 0x70) for index in range(30))
    holes = {address(0x70 + 2 * index): OTHER for index in range(20)}
    cases = [
        act("no liquidator set", liquidators=()),
        act("default not in the set", liquidators=(LIQ,)),
        act("default past every key", liquidators=(address(1), address(2))),
        act("default in a deep set", liquidators=many + (BOSS,)),
        act("default missing from a deep set", liquidators=many),
        act("signer is default"),
        act("signer differs, empty agent map", signer=SIGNER),
        act("signer differs, default not a key", signer=SIGNER, agents={LIQ: SIGNER}),
        act("signer is the direct value", signer=SIGNER, agents={BOSS: SIGNER}),
        act("signer two steps away", signer=SIGNER, agents={BOSS: LIQ, LIQ: SIGNER}),
        act("signer three steps away", signer=SIGNER, agents={BOSS: LIQ, LIQ: HELP, HELP: SIGNER}),
        act("chain ends short of the signer", signer=SIGNER, agents={BOSS: LIQ}),
        act("chain two steps, then a miss", signer=SIGNER, agents={BOSS: LIQ, LIQ: HELP}),
        act("chain through a deep map", signer=SIGNER, agents={**{key: OTHER for key in many[:3] + many[4:19]}, BOSS: many[3], many[3]: many[20], many[20]: SIGNER}),
        act("deep map, chain misses", signer=SIGNER, agents={**{key: OTHER for key in many[:3] + many[4:19]}, BOSS: many[3], many[3]: many[20]}),
        act("tag zero runs all markets", tag=0),
        act("tag 4 runs all markets", tag=4),
        act("run error", run_error=0x77),
        act("single asset", mode="single", asset=5),
        act("single asset zero", mode="single", asset=0),
        act("single asset, classify refuses", mode="single", asset=5, classify={5: (0x99, 0x1234, 0x5678)}),
        act("single asset, spot kind", mode="single", asset=5, classify={5: (OK, 1, 7)}),
        act("single asset, kind 2", mode="single", asset=5, classify={5: (OK, 2, 7)}),
        act("single asset, id in dex 1", mode="single", asset=5, classify={5: (OK, 0, 10007)}, dexes=(MAIN, MAIN)),
        act("single asset, dex 1 not main", mode="single", asset=5, classify={5: (OK, 0, 10007)}, dexes=(MAIN, 2)),
        act("single asset, dex 0 not main", mode="single", asset=5, dexes=(1,)),
        act("single asset, status 4", mode="single", asset=5, dexes=(4,)),
        act("single asset, dex past the table", mode="single", asset=5, classify={5: (OK, 0, 20007)}, dexes=(MAIN, MAIN)),
        act("single asset, id just under dex 1", mode="single", asset=5, classify={5: (OK, 0, 9999)}, dexes=(MAIN,)),
        act("single asset, id at dex 1", mode="single", asset=5, classify={5: (OK, 0, 10000)}, dexes=(MAIN,)),
        act("single asset, run error", mode="single", asset=5, run_error=0x77),
        act("list, empty map", mode="list"),
        act("list, map length 10001", mode="list", map_len=10001),
        act("list, map length 10000, one row", mode="list", map_len=10000, entries=[(LIQ, (1,))], liquidators=(BOSS, LIQ)),
        act("list, entry by the signer", mode="list", signer=LIQ, default=LIQ, entries=[(LIQ, (1,))], liquidators=(LIQ,)),
        act("list, entry is default", mode="list", entries=[(BOSS, (1,))]),
        act("list, other entry signed by itself", mode="list", signer=LIQ, default=BOSS, entries=[(LIQ, (1, 2))], liquidators=(BOSS, LIQ), agents={BOSS: LIQ}),
        pair("list, agent for both", mode="list", entries=[(LIQ, (1, 2))], liquidators=(BOSS, LIQ, SIGNER)),
        act("list, agent for entry", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, (1, 2))], liquidators=(BOSS, LIQ)),
        act("list, agent for entry, two steps", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: HELP, HELP: SIGNER}, entries=[(LIQ, (1,))], liquidators=(BOSS, LIQ)),
        act("list, entry not a liquidator", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, (1,))]),
        act("list, entry not an agent key", mode="list", signer=SIGNER, agents={BOSS: SIGNER}, entries=[(LIQ, (1,))], liquidators=(BOSS, LIQ)),
        act("list, entry chain misses", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: HELP}, entries=[(LIQ, (1,))], liquidators=(BOSS, LIQ)),
        act("list, second entry refused", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER, HELP: OTHER}, entries=[(LIQ, (1,)), (HELP, (2,))], liquidators=(BOSS, LIQ, HELP)),
        act("list, two entries", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER, HELP: SIGNER}, entries=[(HELP, (3, 4)), (LIQ, (1, 2))], liquidators=(BOSS, LIQ, HELP)),
        act("list, three entries", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER, HELP: SIGNER, OTHER: SIGNER}, entries=[(HELP, (3,)), (LIQ, (1,)), (OTHER, (9,))], liquidators=(BOSS, LIQ, HELP, OTHER)),
        act("list, duplicate asset across entries", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER, HELP: SIGNER}, entries=[(HELP, (1, 3)), (LIQ, (1, 2))], liquidators=(BOSS, LIQ, HELP)),
        act("list, same id from two wire assets", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, (1, 2))], liquidators=(BOSS, LIQ), classify={2: (OK, 0, 1)}),
        act("list, duplicate wire id across entries by classify", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER, HELP: SIGNER}, entries=[(HELP, (8,)), (LIQ, (9,))], liquidators=(BOSS, LIQ, HELP), classify={8: (OK, 0, 3), 9: (OK, 0, 3)}),
        act("list, empty asset set", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, ())], liquidators=(BOSS, LIQ)),
        act("list, empty set with a claimed length", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, (), 1)], liquidators=(BOSS, LIQ)),
        act("list, value length 10001", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, (1,), 10001)], liquidators=(BOSS, LIQ)),
        act("list, value length 10000, short set", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, (1,), 10000)], liquidators=(BOSS, LIQ)),
        act("list, second value length 10001", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER, HELP: SIGNER}, entries=[(HELP, (2,), 10001), (LIQ, (1,))], liquidators=(BOSS, LIQ, HELP)),
        act("list, spot first asset", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, (1,))], liquidators=(BOSS, LIQ), classify={1: (OK, 1, 77)}),
        act("list, asset refused by classify", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, (1, 2))], liquidators=(BOSS, LIQ), classify={2: (0x99, 0x31, 0x32)}),
        act("list, spot asset", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, (1, 2))], liquidators=(BOSS, LIQ), classify={2: (OK, 1, 77)}),
        act("list, dex not main", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, (1, 2))], liquidators=(BOSS, LIQ), classify={2: (OK, 0, 10002)}, dexes=(MAIN, 2)),
        act("list, dex past the table", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, (1, 2))], liquidators=(BOSS, LIQ), classify={2: (OK, 0, 10002)}),
        act("list, 30 assets, tree of depth", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, tuple(range(1, 31)))], liquidators=(BOSS, LIQ)),
        act("list, 40 assets over 2 entries", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER, HELP: SIGNER}, entries=[(LIQ, tuple(range(1, 21))), (HELP, tuple(range(21, 41)))], liquidators=(BOSS, LIQ, HELP)),
        act("list, 14 entries over two levels", mode="list", signer=SIGNER, agents={**{key: SIGNER for key in many[:14]}, BOSS: SIGNER}, entries=[(key, (index + 1,)) for index, key in enumerate(many[:14])], liquidators=many + (BOSS,)),
        act("list, 14 entries, last refused", mode="list", signer=SIGNER, agents={**{key: SIGNER for key in many[:13]}, BOSS: SIGNER}, entries=[(key, (index + 1,)) for index, key in enumerate(many[:14])], liquidators=many + (BOSS,)),
        act("list, dex 1 main, dex 0 not", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, (2,))], liquidators=(BOSS, LIQ), classify={2: (OK, 0, 10002)}, dexes=(2, MAIN)),
        act("list, entry chain through a deep map", mode="list", signer=SIGNER, agents={**{key: OTHER for key in many[:3] + many[4:19]}, BOSS: SIGNER, LIQ: many[3], many[3]: many[20], many[20]: SIGNER}, entries=[(LIQ, (1,))], liquidators=(BOSS, LIQ)),
        act("list, entry chain missing inside a deep map", mode="list", signer=SIGNER, agents={**holes, BOSS: SIGNER, LIQ: address(0x81)}, entries=[(LIQ, (1,))], liquidators=(BOSS, LIQ)),
        act("chain missing inside a deep map", signer=SIGNER, agents={**holes, BOSS: address(0x81)}),
        act("list, run error", mode="list", signer=SIGNER, agents={BOSS: SIGNER, LIQ: SIGNER}, entries=[(LIQ, (1, 2))], liquidators=(BOSS, LIQ), run_error=0x77),
    ]
    return cases


def run_case(label, **fields):
    case = dict(label=label, kind="exec", user=USER)
    case.update(fields)
    return case


def row(items, total=1000, amount=500, **fields):
    built = dict(items=items, total=total, amount=amount)
    built.update(fields)
    return built


def exec_cases():
    markets = (b"AAA", b"", b"CCCC", b"D")
    cases = [
        run_case("dex past the table", dex=1),
        run_case("dex past a table of 3", dex=3, dex_count=3),
        run_case("plan refuses", plan_error=0x88),
        run_case("plan refuses with single asset", plan_error=0x88, flag=1, asset=2),
        run_case("nothing to do"),
        run_case("no rows, one reserved", rows_cap=1),
        run_case("markets, no positions", markets=markets),
        run_case("markets, dex row 2 id 7", markets=markets, dex=2, dex_count=3, dex_id=7),
        run_case("flag, asset 2", flag=1, asset=2, markets=markets),
        run_case("flag, asset in dex 7", flag=1, asset=70003, markets=markets),
        run_case("flag, dex past book tables", flag=1, asset=90003, markets=markets),
        run_case("flag, local past the books", flag=1, asset=70004, markets=markets),
        run_case("whole dex, books short", markets=markets, books=2),
        run_case("whole dex, dex id past tables", markets=markets, dex_id=9),
        run_case("dex id product overflow", markets=markets, dex_id=1 << 60),
        run_case("position cross", markets=markets, positions={1: (0, 5)}),
        run_case("position isolated, live", markets=markets, positions={1: (1, 5)}),
        run_case("position isolated, zero word", markets=markets, positions={1: (1, 0)}),
        run_case("position tag 2, live", markets=markets, positions={2: (2, 5)}),
        run_case("positions on both ends", markets=markets, positions={0: (1, 1), 3: (1, 1)}),
        run_case("many positions", markets=tuple(b"M" for _ in range(30)), books=30, positions={index: (index % 2, index % 3) for index in range(30)}),
        run_case("position outside the dex", markets=markets, dex_id=1, positions={5: (1, 1), 10002: (1, 1), 20000: (1, 1)}),
        run_case("single event, no items", rows=[row([])]),
        run_case("isolated event, no items", rows=[row([], tag=1)]),
        run_case("cross hand-over, long", rows=[row([(4, 10, 3000)], ident=9)]),
        run_case("cross hand-over, short", rows=[row([(4, -10, -3000)], ident=9)]),
        run_case("isolated hand-over, long", rows=[row([(4, 10, 3000)], tag=1, ident=9)]),
        run_case("isolated hand-over, short", rows=[row([(4, -10, -3000)], tag=1, ident=9)]),
        run_case("tag 3 row", rows=[row([(4, -10, -3000)], tag=3, ident=9)]),
        run_case("block row present", block=1, rows=[row([(4, 10, 3000)])]),
        run_case("order tag 1", order_tag=1, rows=[row([(4, 10, 3000)])]),
        run_case("order builder fails", order_tag=2, rows=[row([(4, 10, 3000)])]),
        run_case("zero size item skipped", rows=[row([(4, 0, 3000), (5, 2, 100)])]),
        run_case("all zero sizes", rows=[row([(4, 0, 3000)])]),
        run_case("two items share one amount", rows=[row([(4, 10, 300), (5, -20, -700)], total=1000, amount=100)]),
        run_case("three items, odd count ids", rows=[row([(1, 1, 3), (2, 2, 5), (3, 3, 9)], total=17, amount=4)]),
        run_case("four rows of the unrolled copy", rows=[row([(index, 1, 9)], ident=index + 50) for index in range(4)]),
        run_case("seven rows", rows=[row([(index, 1, 9)], ident=index + 50) for index in range(7)]),
        run_case("nine rows", rows=[row([(index, 1, 9)], ident=index + 50) for index in range(9)]),
        run_case("dex map empty", no_map=1, rows=[row([(4, 10, 3000)])]),
        run_case("dex map root missing", no_root=1),
        run_case("empty dex name", dex_name=b"", rows=[row([(4, 10, 3000)])]),
        run_case("cross position in dex 1", dex_id=1, markets=markets, positions={10001: (0, 5)}),
        run_case("two rows after the sentinel", rows=[row([], tag=2), row([(2, 1, 9)], cap=4), row([(2, 1, 9)], cap=7)]),
        run_case("total zero", rows=[row([(4, 10, 3000)], total=0)]),
        run_case("value small gives price 1, long", rows=[row([(4, 10, 3)], total=3, amount=0)]),
        run_case("value small gives price 1, short", rows=[row([(4, -10, -3)], total=3, amount=0)]),
        run_case("value equal size", rows=[row([(4, 10, 10)], total=10, amount=0)]),
        run_case("value one past size", rows=[row([(4, 10, 11)], total=11, amount=0)]),
        run_case("value size minus one", rows=[row([(4, 10, 9)], total=9, amount=0)]),
        run_case("price rest below one, long", rows=[row([(4, 10, 30)], total=30, amount=100)]),
        run_case("price rest above minus one, short", rows=[row([(4, -10, -30)], total=30, amount=-100)]),
        run_case("rest exactly 1", rows=[row([(4, 1, 5)], total=5, amount=4)]),
        run_case("rest exactly 2", rows=[row([(4, 1, 6)], total=6, amount=4)]),
        run_case("rest exactly minus 1", rows=[row([(4, -1, -5)], total=5, amount=-4)]),
        run_case("rest exactly minus 2", rows=[row([(4, -1, -6)], total=6, amount=-4)]),
        run_case("negative amount raises the value", rows=[row([(4, 5, 100)], total=100, amount=-50)]),
        run_case("sign mix: long with negative value", rows=[row([(4, 5, -100)], total=100, amount=20)]),
        run_case("sign mix: short with positive value", rows=[row([(4, -5, 100)], total=100, amount=20)]),
        run_case("value past 2^32", rows=[row([(4, 3, 1 << 40)], total=1 << 40, amount=1 << 39)]),
        run_case("size past 2^32", rows=[row([(4, 1 << 33, 1 << 40)], total=1 << 40, amount=0)]),
        run_case("huge product of shares", rows=[row([(4, 1, 1 << 62)], total=1, amount=1 << 62)]),
        run_case("huge amount saturates high", rows=[row([(4, 1, -(1 << 62))], total=1, amount=(1 << 63) - 1)]),
        run_case("huge negative amount saturates low", rows=[row([(4, -1, (1 << 62))], total=1, amount=-(1 << 63))]),
        run_case("taken part saturates, no overflow", rows=[row([(4, 1, 2)], total=1, amount=(1 << 63) - 1)]),
        run_case("subtraction overflow, long", rows=[row([(4, 1, (1 << 63) - 1)], total=1, amount=-(1 << 62))]),
        run_case("subtraction overflow, short", rows=[row([(4, -1, -(1 << 63) + 1)], total=1, amount=-(1 << 62) * -1)]),
        run_case("subtraction overflow, long, value low", rows=[row([(4, 1, -(1 << 63) + 1)], total=1, amount=(1 << 62))]),
        run_case("subtraction overflow, short, value high", rows=[row([(4, -1, (1 << 63) - 1)], total=1, amount=-(1 << 62))]),
        run_case("product at the limit", rows=[row([(4, 2, (1 << 63) - 2)], total=1 << 63, amount=0)]),
        run_case("product just under the limit", rows=[row([(4, 3, (1 << 63) - 2)], total=1 << 63, amount=0)]),
        run_case("counter at the top", counter=MASK[8] - 1, rows=[row([(1, 1, 9), (2, 1, 9), (3, 1, 9)], total=9, amount=1)]),
        run_case("ids move over rows", rows=[row([(1, 1, 9), (2, 1, 9)], total=9, amount=1), row([(3, 1, 9)], total=9, amount=1)]),
        run_case("sentinel row ends the walk", rows=[row([(1, 1, 9)]), row([], tag=2, ident=3), row([(2, 1, 9)], cap=4)]),
        run_case("sentinel row with item", rows=[row([(1, 2, 9)], tag=2, ident=3)]),
        run_case("row capacity above the length", rows=[row([(1, 1, 9)], cap=5)], rows_cap=6),
        run_case("once word set", once=1, rows=[row([(4, 10, 3000)])]),
        run_case("once word set, flag path", once=1, flag=1, asset=1, markets=markets, rows=[row([(4, 10, 3000)])]),
        run_case("hand-over and cancels", markets=markets, positions={1: (1, 5)}, rows=[row([(1, 10, 3000)], ident=3)]),
    ]
    return cases


def all_cases():
    cases = []
    for layout in COPIES:
        for case in action_cases() + exec_cases():
            cases.append(dict(case, copy=layout["name"]))
    return cases


def relative_slots(image):
    return {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}


# ---- static evidence ----

STUBS = (
    ("0x3c0cc70", "wire asset classifier, asset and both context pointers checked, status, kind and encoded id given. Held by others"),
    ("0x3379490", "drop of a status value; the checked word 0x141 is read back"),
    ("0x36fff10", "liquidation plan, all 7 arguments checked, status or rows of 0x68 given. Not modelled here"),
    ("0x289bfb0, 0x497caf0", "clone of the dex map, both source words checked"),
    ("0x3bb1420", "item row map under the event row; iterator span and context checked, 3 words given"),
    ("0x3987cb0", "block row of 32 bytes, read only when exchange word 0 is 1; 4 arguments checked"),
    ("0x3576710, 0x4855a50", "event sink; sink pointer, user vector, block time, block row and the event row checked"),
    ("0x26e3ef0, 0x4303650, 0x4303db0", "user cancel; book, user, exchange, accumulator and reason 13 checked. Mapped by #354 and #161"),
    ("0x24fb610, 0x4329870, 0x432a100", "flush; accumulator, dex and exchange checked"),
    ("0x36f57f0", "user read; map pointer and key checked. Held by others"),
    ("0x289b0b0, 0x499d800", "clone of the user position map; both source words checked, the tree built by the case"),
    ("0x3bfffd0", "asset id decode; argument and context checked, its output is not read here"),
    ("0x2397010, 0x4a07020", "order row builder, all 8 context pointers read back, tag given. Mapped by #149"),
    ("0x26f4cd0, 0x4cd84f0", "order send; every argument checked, including the 33 byte source and mode word. Mapped by #1036"),
    ("0x28aa700, 0x28a97f0, 0x28a9030, 0x28a9c10, 0x277f220, 0x3402cf0, 0x33f0da0 and copies", "drops; call order recorded"),
)
REAL_HELPERS = (("0x284cc30, 0x493ac40", "u64 set insert"), ("0x284bb50, 0x49277e0", "address set read"), ("0x284bc20, 0x4927a10", "agent map read"), ("0x284fda0, 0x4938930", "action map insert"),
                ("0x33b5620", "consuming map iterator"), ("0x33b9210", "consuming set iterator"), ("0x33a8ab0", "route map insert, replaces and reports a repeated key"),
                ("0x1a9bc20, 0x41e7500, 0x2f32f40, 0x4212e10, 0x1ae9ae0", "node splits"))
GROUP_REASONS = "cold unwind, panic or allocation failure path"
PAST_KEY = "moves the stop test past the last key; poison keys end the walk at the same row"
LENGTH = "node length read at another offset; poison keys end the walk at the same row"
STRIDE = "scan stride of the key walk; poison keys end the walk at the same row"
TALL = "height of 8 or more, not built by the fixtures"
DEAD = "field copied and not read by a stub"
FINITE = "branch needs a value above the finite range; amount times share stays finite"
STALE = "word of an error row that no case reads"
MAGIC = "low bit of the /10000 multiplier changes quotients only far past these ids"
ALLOC = "allocation size off by one byte, not visible in the bump heap"
UNWIND = "kept only for the unwind path"
ITERATOR = "word of an iterator read only by its drop stub"
DANGLING = "dangling pointer of an empty vector, never read"
COPY = "copy length off by one byte; the extra byte is not read"
REPEAT = "repeat of the dex bound passed at entry, it cannot fail"
CLAMP = "the clamp and the direct conversion give the same word"
ROUTE_ROW = "a route refusal writes only the status and first word, the rest of this copy is stale"
EMPTY = "length word of an empty map, read by no stub"
REASONS = {0x23E68AC: LENGTH, 0x23E6D9C: LENGTH, 0x23E6F7A: LENGTH, 0x3424D7E: LENGTH, 0x2725824: LENGTH, 0x23E68D5: STRIDE, 0x23E68F7: STRIDE, 0x3424DA5: STRIDE, 0x3424DC4: STRIDE,
           0x3424DA9: "compare of 21 bytes; the keys here differ in the first 20", 0x23E6D17: TALL, 0x23E6DF7: TALL, 0x23E6F3C: TALL, 0x23E6FE5: TALL, 0x23E70DB: TALL, 0x23E70DF: TALL, 0x23E6DD3: TALL, 0x23E6FD3: TALL,
           0x23E6C0F: EMPTY, 0x23E6C7D: EMPTY, 0x3424F4C: ITERATOR, 0x3424E1F: ITERATOR, 0x3424E3F: ITERATOR, 0x3424E52: ITERATOR, 0x3424E5B: ITERATOR, 0x3424E81: EMPTY, 0x3424E1B: ITERATOR, 0x3425086: ITERATOR,
           0x3424DFF: "descends one edge to the right; the default still misses", 0x23E7068: MAGIC, 0x272558C: MAGIC, 0x27257CC: MAGIC, 0x27257E3: MAGIC,
           0x23E7398: ROUTE_ROW, 0x23E73A5: ROUTE_ROW, 0x23E73CA: ROUTE_ROW, 0x23E73CF: ROUTE_ROW, 0x23E73D4: ROUTE_ROW, 0x3424E8A: ALLOC, 0x2725487: ALLOC, 0x392B7D1: ALLOC, 0x392B7FD: ALLOC, 0x254E847: ALLOC,
           0x3424FCF: UNWIND, 0x3424FD4: UNWIND, 0x3424FD8: UNWIND, 0x3424FE2: UNWIND, 0x272537F: DANGLING, 0x2725AFF: DANGLING, 0x2725D24: DANGLING, 0x254E890: DANGLING, 0x254E929: DANGLING,
           0x2725536: COPY, 0x27261DF: COPY, 0x27262FC: COPY, 0x27256CF: REPEAT, 0x2725E35: REPEAT, 0x2725EA9: REPEAT, 0x27262C1: REPEAT, 0x2725CA0: "register overwritten before a read", 0x2725F81: "sign mask bit; the low bit does not change the range test",
           0x2725F8E: FINITE, 0x2725FA5: FINITE, 0x2725FEC: CLAMP, 0x2725FF6: CLAMP, 0x2726055: "rest 0 and rest 1 give price 1 alike", 0x27260B5: "32 bit divide fast path, same quotient", 0x27264A4: "compare after a saturated subtraction, far from the bound",
           0x27264E1: "compare after a saturated subtraction, far from the bound", 0x23E6D1D: TALL, 0x23E6D25: TALL, 0x23E6D2C: TALL, 0x23E6D33: TALL, 0x23E6D3A: TALL, 0x23E6D41: TALL, 0x23E6D48: TALL, 0x23E6D4F: TALL, 0x23E6D56: TALL, 0x23E6D5A: TALL}
for _start, _end in ((0x23E6E03, 0x23E6E41), (0x23E6F50, 0x23E6F75), (0x23E6FF3, 0x23E7018)):
    for _at in range(_start, _end):
        REASONS[_at] = TALL


def rows_of(image, start):
    begin, end = image.exact_fde(start)
    return decode_range(image, begin, end)


def direct_callers(image, targets):
    base, text = image.text_bytes()
    found = {target: [] for target in targets}
    at = text.find(b"\xe8")
    while 0 <= at <= len(text) - 5:
        target = base + at + 5 + struct.unpack_from("<i", text, at + 1)[0]
        if target in found:
            found[target].append(base + at)
        at = text.find(b"\xe8", at + 1)
    return found


def groups(image):
    first = COPIES[0]
    return [("handler primary", *image.exact_fde(first["entry"])), ("route shared", *image.exact_fde(ROUTE)), ("agent chain primary", *image.exact_fde(first["chain"])), ("executor primary", *image.exact_fde(first["run"])),
            ("event row shared", *image.exact_fde(EVENT_ROW)), ("list clone primary", *image.exact_fde(first["clone_rows"]))]


def stepped_groups(image):
    rows = list(groups(image))
    for layout in COPIES[1:]:
        rows.append(("handler " + layout["name"], *image.exact_fde(layout["entry"])))
        rows.append(("agent chain " + layout["name"], *image.exact_fde(layout["chain"])))
        rows.append(("executor " + layout["name"], *image.exact_fde(layout["run"])))
    return rows


CONSTANT_SITES = (
    ("handler", "liquidator set root, exchange +0x3948", 0x23E674D, b"\x4c\x8b\xb9\x48\x39\x00\x00", 0x3948),
    ("handler", "refusal 0x23 at the first gate", 0x23E6754, b"\x66\xb8\x23\x00", NO_LIQUIDATOR),
    ("handler", "agent map root, exchange +0x8d0", 0x23E686B, b"\x48\x8b\x80\xd0\x08\x00\x00", 0x8D0),
    ("handler", "request tag 2 is one asset", 0x23E6A57, b"\x48\x83\xf8\x02", 2),
    ("handler", "ok status compare", 0x23E6A83, b"\x3d\x86\x01\x00\x00", OK),
    ("handler", "kind 1 refusal 0x15e", 0x23E6AA3, b"\x66\x41\xc7\x46\x08\x5e\x01", WRONG_KIND),
    ("handler", "map length limit", 0x23E6AEF, b"\x49\x81\xf9\x10\x27\x00\x00", LIST_LIMIT),
    ("handler", "limit refusal 0x143", 0x23E6AFC, b"\x66\x41\xc7\x46\x08\x43\x01", TOO_MANY),
    ("handler", "refusal 0x7c", 0x23E6B44, b"\x66\xb8\x7c\x00", NOT_AGENT),
    ("handler", "dex row byte +0x230 must be 3", 0x23E6C63, b"\x80\xbc\x03\x30\x02\x00\x00\x03", MAIN),
    ("handler", "refusal 0x61", 0x23E746D, b"\x66\x41\xc7\x46\x08\x61\x00", NOT_MAIN),
    ("handler", "set length limit", 0x23E6E89, b"\x48\x81\xfd\x10\x27\x00\x00", LIST_LIMIT),
    ("handler", "executor gets dex index 0", 0x23E72ED, b"\x31\xc9", 0),
    ("route", "default liquidator in the map, 0x25", 0x3424E11, b"\x66\xc7\x03\x25\x00", DEFAULT_LISTED),
    ("route", "repeated asset, 0x24", 0x3425128, b"\x66\xc7\x00\x24\x00", DUPLICATE),
    ("executor", "row stride", 0x2725420, b"\x48\x6b\xc1\x68", ROW_STRIDE),
    ("executor", "cancel reason in the asset arm", 0x2725680, b"\x41\xb8\x0d\x00\x00\x00", CANCEL_REASON),
    ("executor", "cancel reason in the dex arm", 0x2725A2F, b"\x41\xb8\x0d\x00\x00\x00", CANCEL_REASON),
)


def constants(image):
    rows = []
    for role, name, va, pattern, value in CONSTANT_SITES:
        at = image.offset(va)
        if bytes(image.blob[at:at + len(pattern)]) != pattern:
            raise EvidenceError("constant moved: " + name)
        rows.append({"function": role, "name": name, "address": "%#x" % va, "bytes": pattern.hex(), "value": value})
    return rows


def call_map(image):
    wanted = [layout["entry"] for layout in COPIES] + [layout["run"] for layout in COPIES] + [ROUTE]
    direct = direct_callers(image, wanted)
    return [{"function": "%#x" % target, "direct_calls_from": ["%#x" % site for site in direct[target]], "callers": sorted({"%#x" % image.fde(site)[0] for site in direct[target]})} for target in wanted]


def copy_calls(image):
    rows = []
    for layout in COPIES:
        for name in ("entry", "run"):
            rows.append({"copy": layout["name"], "entry": "%#x" % layout[name], "calls": ["%#x" % row.target for row in rows_of(image, layout[name]) if row.op == "call" and row.target]})
    return rows


# ---- mutation ----

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
    machine.step_limit = MUTANT_STEP_LIMIT
    by_va = {}
    for index, touched in enumerate(reached):
        if cases[index].get("copy") != "primary":
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
                    del first_kill[40:]
                    break
            machine.patches = {}
            machine.cache.pop(va, None)
            results.append({"group": role, "va": va, "kind": kind, "result": "killed" if failed else "survived", "by": failed.split(":")[0] if failed else ""})
    return results


# ---- evidence ----

def outcome_of(case):
    try:
        want = action_spec(case) if case["kind"] == "action" else run_spec(case)
    except Panicked as panic:
        return "panic " + str(panic)
    if case["kind"] == "action":
        return "action ok" if want["tag"] == RESULT_OK else "action refused %#x" % want["status"]
    if want["status"] != OK:
        return "executor plan refused"
    return "executor sends orders" if any(event[0] == "send" for event in want["events"]) else "executor no order"


def path_rows():
    return [
        ("1", "liquidator gate", "0x23e66f0", "the action's second address (+0x34) must be in the set at +0x3948; miss = 0x23 (35)"),
        ("2", "signer gate", "0x23e66f0", "signer == that address passes; else the address must be a key of the agent map +0x8d0, miss = 0x23; then follow value +0x98 key to key until a value equals the signer, a missing key = 0x7c (124) with signer and address"),
        ("3a", "one asset, tag 2", "0x3c0cc70", "classifier status is passed out; kind 1 = 0x15e (350); encoded id / 10000 past the dex table panics; dex row byte +0x230 != 3 = 0x61 (97); flag 1"),
        ("3b", "list, odd tag", "0x23e66f0", "map length > 10000 or one set length > 10000 = 0x143 (323); each asset as in 3a into a u64 set"),
        ("3c", "list entry signer", "0x284bb50, 0x284bc20, 0x275f050", "the entry address must be in the set +0x3948 (0x23); signer == address passes; else key of the agent map (0x23) and chain (0x7c)"),
        ("3d", "other tags", "0x23e66f0", "even tag other than 2: no assets, flag 0"),
        ("4", "route", "0x3424d20", "default address listed = 0x25 (37); walks the map in key order, pushes each address after the default, inserts each asset, a repeated asset = 0x24 (36) with the id"),
        ("5", "execute", "0x2725150", "called with dex index 0 always, the user at +0x20, flag, id and the route"),
        ("6", "plan", "0x36fff10", "status other than 0x186 is returned as is; else rows of 0x68"),
        ("7", "events", "0x392b7b0, 0x3576710", "one event per row: name Isolated when word 0 is 1 else Cross, +0x30 and signed +0x38 / 1e6 as doubles, block time, block row"),
        ("8a", "cancel, one asset", "0x26e3ef0, 0x24fb610", "book table +0x3370 row id/10000, book id%10000, reason 13, flush by id/10000"),
        ("8b", "cancel, whole dex", "0x36f57f0, 0x26e3ef0", "for every market of the dex, id = dex row +0x30 * 10000 + index; a position with word 0 != 0 and +0x10 != 0 keeps its orders; all others cancel with reason 13"),
        ("9", "order ids", "0x2725150", "for each row one id per item from exchange +0x38, saturating at u64::MAX, ids taken even for skipped items"),
        ("10", "hand-over price", "0x2725150", "for each item of size != 0: share = |value| / row +0x30 (0.0 when +0x30 is 0); rest = value - saturating(row +0x38 * share), saturating with a log; long rest >= 1, short rest <= -1; px = floor(|rest| / |size|), at least 1; px * |size| >= i64::MAX panics"),
        ("11", "send", "0x2397010, 0x26f4cd0, 0x24fb610", "order row from 8 pointers; tag 2 panics; send with source byte 1 and 32 block bytes; mode bytes k, b, k, b with k = 1 when row word 0 is 0 else 2 and b = 1 for size < 0"),
        ("12", "end", "0x2725150", "row word 0 == 2 ends the walk and frees the rest; returns the +0x28 word of every row"),
    ]


def reference_rows():
    return [
        ("second address has no agent entry and signer differs", "124 (UnauthorizedDelegate)", "35", "signer is not the default liquidator and the address is not a key of +0x8d0"),
        ("agent relation", "one set lookup under the default", "chain walk over key to value, any length", "value +0x98 of the row is the next key"),
        ("entry address in the list", "no check", "must be a liquidator and the signer or its agent chain must reach it", "refusal 35 or 124"),
        ("default address listed", "37 inside the entry loop", "37 in 0x3424d20 after all assets passed", "asset refusals come first"),
        ("repeated asset", "36 inside the entry loop", "36 in 0x3424d20 after all assets passed", "same order change"),
        ("byte +0x230 == 3", "market is liquidation ready, trading status", "byte of the dex row, not of the market", "read by encoded id / 10000 only"),
        ("dex of the executor", "resolved perp/dex market", "index 0 from xor ecx, ecx", "the id's dex is used only by the gate and the book walk"),
    ]


def gate_samples(image):
    harness = Harness(image)
    rows = []
    for case in action_cases():
        if case["label"] in ("default not in the set", "signer differs, empty agent map", "signer differs, default not a key", "signer is the direct value", "signer three steps away", "chain ends short of the signer", "single asset, spot kind", "single asset, dex 1 not main", "list, entry is default", "list, entry not a liquidator", "list, entry chain misses", "list, duplicate asset across entries", "list, map length 10001", "list, value length 10001"):
            if compare_run(harness, case):
                raise EvidenceError("sample mismatch: " + case["label"])
            want = action_spec(case)
            rows.append((case["label"], "ok" if want["tag"] == RESULT_OK else "%#x" % want["status"], ",".join(event[0] for event in want["events"]) or "none"))
    return rows


def price_samples(image):
    harness = Harness(image)
    rows = []
    for size, value, total, amount in ((10, 3000, 1000, 500), (-10, -3000, 1000, 500), (10, 3, 3, 0), (10, 10, 10, 0), (10, 11, 11, 0), (10, 30, 30, 100), (-10, -30, 30, -100), (5, 100, 100, -50), (5, -100, 100, 20), (-5, 100, 100, 20), (4, 100, 0, 7), (2, (1 << 63) - 1, 1, -(1 << 62))):
        case = run_case("sample", rows=[row([(4, size, value)], total=total, amount=amount)])
        if compare_run(harness, case):
            raise EvidenceError("price sample mismatch")
        send = [event for event in harness.events if event[0] == "send"][0]
        rows.append((size, value, total, amount, send[2], send[4], send[5], send[6], "%#x" % send[7], harness.logs))
    return rows


def analyse(image, full=True):
    cases = all_cases()
    harness = Harness(image)
    machine = harness.machine
    mismatches, first = 0, ""
    reached = []
    outcomes = {}
    for case in cases:
        machine.seen = set()
        failed = compare_run(harness, case)
        reached.append(frozenset(machine.seen))
        if failed:
            mismatches += 1
            first = first or failed
        key = outcome_of(case)
        outcomes[key] = outcomes.get(key, 0) + 1
    touched = set().union(*reached)
    functions = []
    for role, begin, end in stepped_groups(image):
        rows = decode_range(image, begin, end)
        base = image.offset(begin)
        functions.append({"role": role, "start": "%#x" % begin, "end": "%#x" % end, "bytes": end - begin, "sha256": hashlib.sha256(bytes(image.blob[base:base + end - begin])).hexdigest(),
                          "instructions": len(rows), "instructions_stepped": sum(1 for row in rows if row.va in touched)})
    evidence = {
        "target_sha256": SHA256,
        "functions": functions,
        "call_map": call_map(image),
        "copy_calls": copy_calls(image),
        "constants": constants(image),
        "stubs": [{"edge": edge, "role": role} for edge, role in STUBS],
        "real_helpers": [{"function": edge, "role": role} for edge, role in REAL_HELPERS],
        "cases": {"total": len(cases), "per_copy": len(cases) // len(COPIES), "action_per_copy": sum(1 for case in cases if case["kind"] == "action") // len(COPIES), "executor_per_copy": sum(1 for case in cases if case["kind"] == "exec") // len(COPIES), "outcomes": dict(sorted(outcomes.items()))},
        "mismatches": mismatches,
        "first_mismatch": first,
        "instructions_stepped": machine.steps,
    }
    results = None
    if full:
        results = run_mutants(image, reached, cases)
        summary_rows = {}
        for row_ in results:
            summary_rows[row_["result"]] = summary_rows.get(row_["result"], 0) + 1
        evidence["mutations"] = {name: summary_rows.get(name, 0) for name in ("killed", "survived", "unreached")}
    return evidence, results


def reason_for(row_):
    return REASONS.get(row_["va"], GROUP_REASONS)


def write_tsv(path, header, rows):
    lines = ["\t".join(header)] + ["\t".join(str(item) for item in row_) for row_ in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


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
    write_tsv(out / "reference-diffs.tsv", ("point", "reference_text", "node_94_bytes", "note"), reference_rows())
    write_tsv(out / "gate-samples.tsv", ("label", "result", "calls"), gate_samples(image))
    write_tsv(out / "price-samples.tsv", ("size", "value", "row_total", "row_amount", "price", "abs_size", "product", "buy", "mode", "logs"), price_samples(image))
    lines = ["group\tva\tkind\tresult\tkilled_by\treason"]
    for row_ in results:
        reason = "" if row_["result"] == "killed" else reason_for(row_)
        lines.append("%s\t%#x\t%s\t%s\t%s\t%s" % (row_["group"], row_["va"], row_["kind"], row_["result"], row_["by"], reason))
    (out / "mutations.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print("cases %d, mismatches %d, mutants %r" % (evidence["cases"]["total"], evidence["mismatches"], evidence["mutations"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
