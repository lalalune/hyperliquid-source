#!/usr/bin/env python3
"""Pin the node #94 book mid sampler from ELF bytes: price per book, fallbacks, asset keys, bucket flag.

`0x4cdf580` and its copies `0x4cdfe00` and `0x26f8d50` run once per call of their block hosts. They
take the best bid and ask of each main perp book and each spot book, make one price per asset, sort
the prices by a u32 asset key, hand each to the per-asset sample writer, then compare the time bucket
with the last one seen and pass the result to the status step. The real bytes of the three copies, the
top readers, the spot price fallback, the asset key encoder and the map insert, split and drain run in
a Python evaluator with only the edges stubbed. A separately written specification predicts every edge
call, and every condition, immediate and field offset of the first copy is flipped to show the run can
tell. No objdump or readelf output is parsed, and the binary is never executed. Standard library only.
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

FALLBACK = 0x32780D0
FALLBACK_TOP = 0x3C18D90
COLLECT = 0x3BD5470
MEDIAN = 0x359CA70
SPOT_KEY = 0x3C0CEA0
SAMPLE_WRITER = 0x392B930
RESULT_DROP = 0x3379490
STATUS_STEP = 0x3373DC0
STATUS_BODY = 0x392FCC0
STATUS_CALL = 0x3373E02
STATUS_NAME = 0x5A7FD8
STATUS_TEXT = b"action_delayer_log_status"
SAMPLE_NAME = 0x5A8004
SAMPLE_TEXT = b"deterministic_vty_alert_n_bucket_samples"
TIMER_LIMITS = 0x205E70
ERROR_WORD = 0x141
BOOK_STRIDE = 0xD8
ASSET_STRIDE = 0x30
STATE_STRIDE = 0x60
PAIR_STRIDE = 0x20
TOKEN_STRIDE = 0xE8
MAP_LEAF = 0x90
KEY_SPOT = 10000
KEY_DEX_SHIFT = 100000
KEY_OUTCOME = 100000000
KEY_NONE = 0xFFFFFFFF
KEY_LAST_PLAIN = 0x5F45A5F

SLOT_SAMPLE = 0x57748D8
SLOT_OUTCOME = 0x57738C8
SLOT_GROW = 0x5774458
SLOT_SORT = 0x5775078
SLOT_ALLOC = 0x576DFD8
SLOT_ALLOC_FAILED = 0x576DFB8
SLOT_ALLOC_FAILED_MAP = 0x576E020
SLOT_FREE = 0x576E010
SLOT_MEMCPY = 0x576DFE0
SLOT_MEMMOVE = 0x576E0E0
SLOT_PANIC = 0x576E470
SLOT_BOUNDS = 0x576DFC8
SLOT_MUL = 0x576E1B0
SLOT_ADD = 0x576E118
SLOT_SUB = 0x576E150
SLOT_UNWRAP = 0x576E048
SLOT_NAMES = {SLOT_SAMPLE: "per-asset sample writer, stubbed", SLOT_OUTCOME: "outcome token lookup, stubbed", SLOT_GROW: "grow a u64 vector, stubbed",
              SLOT_ALLOC: "allocate, stubbed", SLOT_FREE: "free, stubbed", SLOT_ALLOC_FAILED: "allocation failure", SLOT_MEMCPY: "memcpy, stubbed", SLOT_MEMMOVE: "memmove, stubbed",
              SLOT_PANIC: "panic with Location", SLOT_BOUNDS: "index bounds panic", SLOT_MUL: "multiply overflow panic", SLOT_ADD: "add overflow panic",
              SLOT_SUB: "subtract overflow panic", SLOT_UNWRAP: "Result unwrap panic"}

LOC_PERPS = 0x56E9B10
LOC_METAS = 0x56E9AE0
LOC_TOP = 0x56E9FE8
LOC_ASSET = 0x56F21C0
LOC_TOKEN = 0x56F21F0
LOC_SZ = 0x56F3350
LOC_DECIMALS = 0x56F2258
LOC_PAIR = 0x5714C70

# The second copy works on the same exchange fields 0xa80 further on, except the spot metadata.
COPIES = (
    dict(name="first", entry=0x4CDF580, top_perp=0x3C18B70, top_spot=0x4A07680, insert=0x4939BD0, drain=0x4949660, perps=0x3370, metas=0x5C0, spots=0x3388,
         network=0x8F2, delay=0x31B8, status_map=0x3228, powers=0x6F7470, loc_top=0x5733F50, loc_counter=0x5743238, loc_spot=0x5742320, loc_math=0x5744C20, loc_state=0x57444C0),
    dict(name="second", entry=0x4CDFE00, top_perp=0x3C18B70, top_spot=0x4A07680, insert=0x4939BD0, drain=0x4949660, perps=0x3DF0, metas=0x1040, spots=0x3E08,
         network=0x1372, delay=0x3C38, status_map=0x3CA8, powers=0x6F7470, loc_top=0x5733F50, loc_counter=0x5743238, loc_spot=0x5742320, loc_math=0x5744C20, loc_state=0x57444C0),
    dict(name="third", entry=0x26F8D50, top_perp=0x3C18B70, top_spot=0x23973D0, insert=0x285EDE0, drain=0x286F7E0, perps=0x3370, metas=0x5C0, spots=0x3388,
         network=0x8F2, delay=0x31B8, status_map=0x3228, powers=0x3E0E90, loc_top=0x56C5540, loc_counter=0x56BD178, loc_spot=0x56BB460, loc_math=0x56BDF70, loc_state=0x56BD1A8),
)
FIRST = COPIES[0]

HOSTS = ((0x4CDF580, 0x470F7A5, 0x470E9A0, 0x4CDF335, 0x4CDF180), (0x4CDFE00, 0x47172FA, 0x47162D0, 0x4CDF53F, 0x4CDF370), (0x26F8D50, 0x222A615, 0x22297C0, 0x26F8D15, 0x26F8B60))

LOCATION_NAMES = {LOC_PERPS: "perp vector first entry", LOC_METAS: "metadata vector first entry", LOC_TOP: "top reader, leaf with no parent", LOC_ASSET: "asset key to asset row",
                  LOC_TOKEN: "spot pair to token row", LOC_SZ: "6 - szDecimals", LOC_DECIMALS: "quote weiDecimals - base szDecimals", LOC_PAIR: "spot key encoder pair row"}

SIDE_NODE = dict(parent=0x160, keys=0x168, stride=8, index=0x1C0, length=0x1C2, edges=0x1C8, size=0x228)
SET_NODE = dict(parent=0, keys=8, stride=8, index=0x60, length=0x62, edges=0x68, size=0xC8)
NODE_KEYS = 11
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
HEAP_SIZE = 0x400000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 20000000
MUTANT_STEP_LIMIT = 150000
FAKE_MEMCPY = 0x7E000010
FAKE_MEMMOVE = 0x7E000020

EX = HEAP_BASE + 0x1000
NOW = EX + 0x5000
PERP_VEC = NOW + 0x100
META_VEC = PERP_VEC + 0x400
BUMP = META_VEC + 0x1000
FIELD_PAIRS = 0x1F8
FIELD_TOKENS = 0x210
FIELD_META = 0x90

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



# ---- specification, written from the disassembly as prose, never from a run ----

def pack_date(year, ordinal, flags=0):
    return ((year << 13) | (ordinal << 4) | flags) & MASK[4]


def signed32(value):
    value &= MASK[4]
    return value - (1 << 32) if value & SIGN[4] else value


def abs64(key):
    """The readers keep the key when its negation is negative, so i64::MIN stays 1 << 63."""
    raw = key & MASK[8]
    negated = -key & MASK[8]
    return raw if negated & SIGN[8] else negated


class Side:
    """One price tree: ordered keys, or a hollow leaf whose first key sits `up` levels above it."""

    def __init__(self, keys=(), height=None, hollow=None, claimed=None, null_root=False):
        self.keys = list(keys)
        self.height = height
        self.hollow = hollow
        self.claimed = claimed
        self.null_root = null_root


class Book:
    def __init__(self, bid=(), ask=(), last=0, index=None):
        self.bid = bid if isinstance(bid, Side) else Side(bid)
        self.ask = ask if isinstance(ask, Side) else Side(ask)
        self.last = last
        self.index = index


class Case:
    def __init__(self, label, perps=(), assets=None, states=None, dex=0, halted=(), spots=(), pairs=None, tokens=None, outcomes=None,
                 now=(pack_date(2026, 303), 3600, 250000000), bucket=60000, seen=0, network=1, no_perps=False, no_metas=False, perp_vector=1, meta_vector=1,
                 alloc_fails=False, width=3, direct=False):
        self.label, self.perps, self.dex, self.halted, self.spots = label, list(perps), dex, tuple(halted), list(spots)
        self.assets = [2] * max(len(self.perps), 1) if assets is None else list(assets)
        self.states = [1000 + 7 * index for index in range(max(len(self.perps), 1))] if states is None else list(states)
        self.pairs = [(index, index + 1) for index in range(len(self.spots))] if pairs is None else list(pairs)
        self.tokens = [(2, 8)] * (len(self.spots) + 2) if tokens is None else list(tokens)
        self.outcomes = dict(outcomes or {})
        self.now, self.bucket, self.seen, self.network = now, bucket, seen, network
        self.no_perps, self.no_metas, self.perp_vector, self.meta_vector = no_perps, no_metas, perp_vector, meta_vector
        self.alloc_fails, self.width, self.direct = alloc_fails, width, direct

    def size(self):
        return len(self.perps) + len(self.spots)


class SpecPanic(Exception):
    pass


def side_top(side, location):
    if side.null_root:
        return 0
    if side.claimed == 0 or (not side.keys and side.hollow is None):
        return 0
    if side.hollow is not None:
        up, key = side.hollow
        if key is None:
            raise SpecPanic(("panic", location))
        return abs64(key)
    return abs64(side.keys[0])


def book_tops(book, location=LOC_TOP):
    return side_top(book.bid, location), side_top(book.ask, location)


def book_mid(bid, ask):
    """Mean with no overflow, floored; either side empty gives 0."""
    if not bid or not ask:
        return 0
    return (bid & ask) + ((bid ^ ask) >> 1)


def median_of(values):
    ordered = sorted(values)
    if len(ordered) & 1:
        return ordered[len(ordered) // 2]
    low, high = ordered[len(ordered) // 2 - 1], ordered[len(ordered) // 2]
    return (low & high) + ((low ^ high) >> 1)


def book_fallback(book):
    """Median of the nonzero tops and the stored last price at +0x78, or that last price if the median is 0."""
    bid, ask = book_tops(book)
    values = [value for value in (bid, ask) if value] + [book.last]
    return median_of(values) or book.last


def date_days(word):
    date = signed32(word)
    year = date >> 13
    ordinal = (word >> 4) & 0x1FF
    shifted, extra = year - 1, 0
    if year <= 0:
        cycles = (1 - year) // 400 + 1
        shifted += 400 * cycles
        extra = -146097 * cycles
    return ordinal + extra + (shifted * 1461 >> 2) - shifted // 100 + (shifted // 100 >> 2) - 719163


def unix_millis(now):
    return max(0, (date_days(now[0]) * 86400 + now[1]) * 1000 + now[2] // 1000000)


def perp_key(raw):
    if raw <= 9999:
        return raw
    return raw + KEY_DEX_SHIFT if raw <= KEY_LAST_PLAIN else KEY_NONE


def spot_key(case, index):
    if index >= len(case.pairs):
        raise SpecPanic(("bounds", index, len(case.pairs), LOC_PAIR))
    token = case.pairs[index][0]
    outcome = case.outcomes.get(token)
    if outcome is None or outcome[1] >= 2:
        return KEY_SPOT + index
    value = outcome[0] * 10
    value = MASK[8] if value > MASK[8] else value + outcome[1]
    value = min(value, MASK[8]) + KEY_OUTCOME
    return value if value <= MASK[4] else KEY_NONE


def power(exponent):
    return float("1e%d" % exponent)


def perp_prices(case, copy, prices):
    mids = []
    for book in case.perps:
        bid, ask = book_tops(book)
        mids.append(book_mid(bid, ask))
    for offset, mid in enumerate(mids):
        whole = case.dex * 10000
        if whole > MASK[8]:
            raise SpecPanic(("mul overflow", copy["loc_math"]))
        raw = whole + offset
        if raw > MASK[8]:
            raise SpecPanic(("add overflow", copy["loc_math"]))
        if not mid:
            at = raw % 10000
            if at >= len(case.states):
                raise SpecPanic(("bounds", at, len(case.states), copy["loc_state"]))
            mid = case.states[at]
        key = perp_key(raw)
        if raw // 10000 != case.dex or raw % 10000 >= len(case.assets):
            raise SpecPanic(("panic", LOC_ASSET))
        decimals = case.assets[raw % 10000]
        if decimals >= 7:
            raise SpecPanic(("sub overflow", LOC_SZ))
        prices[key] = float(mid) / power(6 - decimals)


def spot_prices(case, copy, prices):
    for position, book in enumerate(case.spots):
        bid, ask = book_tops(book, copy["loc_top"])
        mid = book_mid(bid, ask)
        index = position if book.index is None else book.index
        if not mid:
            if index >= len(case.spots):
                raise SpecPanic(("bounds", index, len(case.spots), copy["loc_spot"]))
            mid = book_fallback(case.spots[index])
        key = spot_key(case, index)
        base, quote = case.pairs[index]
        if quote >= len(case.tokens) or base >= len(case.tokens):
            raise SpecPanic(("panic", LOC_TOKEN))
        difference = case.tokens[quote][1] - case.tokens[base][0]
        if difference < 0:
            raise SpecPanic(("sub overflow", LOC_DECIMALS))
        prices[key] = float(mid) / power(difference)


def spec_run(case, copy=FIRST):
    events = []
    result = {"stop": None, "events": events, "seen": case.seen}
    try:
        if case.direct:
            events.append(("fallback", book_fallback(case.spots[0])))
            return result
        if case.no_perps:
            raise SpecPanic(("unwrap", ERROR_WORD, LOC_PERPS))
        events.append(("drop result", ERROR_WORD))
        if case.no_metas:
            raise SpecPanic(("unwrap", ERROR_WORD, LOC_METAS))
        events.append(("drop result", ERROR_WORD))
        count = len(case.perps)
        if count:
            events.append(("alloc", count * 8))
            if case.alloc_fails:
                raise SpecPanic(("alloc failed", 8, count * 8))
        prices = {}
        perp_prices(case, copy, prices)
        if count:
            events.append(("free", count * 8))
        spot_prices(case, copy, prices)
    except SpecPanic as caught:
        result["stop"] = caught.args[0]
        return result
    now = struct.pack("<III", *case.now).hex()
    for key in sorted(prices):
        events.append(("sample", key, struct.pack("<d", prices[key]).hex(), now))
    bucket = unix_millis(case.now) // case.bucket
    events.append(("status step", STATUS_NAME, len(STATUS_TEXT), "7b14ae47e17a843f9a9999999999a93f", int(bucket > case.seen), case.network))
    result["seen"] = max(bucket, case.seen)
    return result


def tree_height(count, width):
    height = 0
    while (width + 1) ** (height + 1) - 1 < count:
        height += 1
    return height


def split(keys, width, height):
    """Separators and child key lists of one node; short lists become a keyless spine."""
    if height == 0:
        return keys, None
    if len(keys) <= 1:
        return [], [keys]
    below = (width + 1) ** height - 1
    count = 2
    while count * below + count - 1 < len(keys):
        count += 1
    share = (len(keys) - (count - 1)) / count
    separators, children, start = [], [], 0
    for index in range(1, count):
        at = int(share * index) + index - 1
        children.append(keys[start:at])
        separators.append(keys[at])
        start = at + 1
    children.append(keys[start:])
    return separators, children

# ---- harness: real bytes, edges stubbed, every edge argument recorded ----

def ramp(size, start):
    """Non-periodic filler, so that a wrong field offset reads a wrong value."""
    return bytes((start + index * 37) & 0xFF | 1 for index in range(size))


class Harness:
    def __init__(self, image, copy=FIRST):
        self.image = image
        self.machine = Machine(image)
        machine = self.machine
        self.relative = {slot: addend for slot, kind, addend, _ in image.relocations() if kind == 8}
        relative = self.relative
        for slot in (SLOT_SAMPLE, SLOT_OUTCOME, SLOT_GROW, SLOT_SORT, SLOT_ALLOC, SLOT_ALLOC_FAILED, SLOT_ALLOC_FAILED_MAP, SLOT_FREE, SLOT_PANIC, SLOT_BOUNDS, SLOT_MUL, SLOT_ADD, SLOT_SUB, SLOT_UNWRAP):
            machine.memory.statics[slot] = relative[slot]
        machine.memory.statics[SLOT_MEMCPY] = FAKE_MEMCPY
        machine.memory.statics[SLOT_MEMMOVE] = FAKE_MEMMOVE
        machine.slots = {relative[SLOT_SAMPLE]: self.on_sample, relative[SLOT_OUTCOME]: self.on_outcome, relative[SLOT_GROW]: self.on_grow,
                         relative[SLOT_ALLOC]: self.on_alloc, relative[SLOT_ALLOC_FAILED]: self.on_alloc_failed, relative[SLOT_FREE]: self.on_free,
                         relative[SLOT_PANIC]: self.on_panic, relative[SLOT_BOUNDS]: self.on_bounds, relative[SLOT_MUL]: self.on_mul, relative[SLOT_ADD]: self.on_add,
                         relative[SLOT_SUB]: self.on_sub, relative[SLOT_UNWRAP]: self.on_unwrap, FAKE_MEMCPY: self.on_memcpy, FAKE_MEMMOVE: self.on_memcpy}
        self.select(copy)
        self.top = HEAP_SIZE
        self.bump = BUMP
        self.events = []
        self.live = {}

    def select(self, copy):
        self.copy = copy
        machine = self.machine
        begin, end = self.image.exact_fde(copy["entry"])
        self.entry_range = (begin, end)
        real = {copy["entry"], copy["top_perp"], copy["top_spot"], copy["insert"], copy["drain"], FALLBACK, FALLBACK_TOP, COLLECT, MEDIAN, SPOT_KEY}
        real.update(call_targets(self.image, copy["insert"]))
        machine.real = frozenset(real)
        machine.calls = {RESULT_DROP: self.on_drop, STATUS_STEP: self.on_status}

    # layout helpers

    def alloc(self, size):
        at = self.bump
        self.bump += (size + 15) & ~15
        if self.bump > HEAP_BASE + HEAP_SIZE:
            raise Halt("harness heap too small")
        return at

    def put(self, addr, width, value):
        self.machine.memory.write(addr, width, value)

    def build_tree(self, at, keys, shape, width, height=None, tempt=None):
        """(root, height, length) at `at`; unused key slots hold a tempting key."""
        keys = list(keys)
        memory = self.machine.memory

        def make(items, parent, slot, level):
            node = self.alloc(shape["size"])
            memory.put_bytes(node, bytes(shape["size"]))
            memory.put_bytes(node + shape["edges"], struct.pack("<Q", LEAF_EDGE) * 12)
            self.put(node + shape["parent"], 8, parent)
            self.put(node + shape["index"], 2, slot)
            separators, children = split(items, width, level)
            self.put(node + shape["length"], 2, len(separators))
            for index, key in enumerate(separators):
                self.put(node + shape["keys"] + index * shape["stride"], 8, key)
            if tempt is not None:
                for index in range(len(separators), NODE_KEYS):
                    self.put(node + shape["keys"] + index * shape["stride"], 8, tempt)
            for index, child in enumerate(children or ()):
                self.put(node + shape["edges"] + index * 8, 8, make(child, node, index, level - 1))
            return node

        level = tree_height(len(keys), width) if height is None else height
        self.put(at, 8, make(keys, 0, 0, level))
        self.put(at + 8, 8, level)
        self.put(at + 0x10, 8, len(keys))

    def build_hollow(self, at, up, key):
        """An empty leaf; its first key, if any, is `up` levels above it."""
        memory = self.machine.memory
        shape = SIDE_NODE
        child = 0
        root = 0
        for level in range(up + 1):
            node = self.alloc(shape["size"])
            memory.put_bytes(node, bytes(shape["size"]))
            memory.put_bytes(node + shape["edges"], struct.pack("<Q", LEAF_EDGE) * 12)
            self.put(node + shape["keys"], 8, 0x7777)
            if child:
                self.put(node + shape["edges"], 8, child)
                self.put(child + shape["parent"], 8, node)
            if level == up and key is not None:
                self.put(node + shape["length"], 2, 1)
                self.put(node + shape["keys"], 8, key)
            child = root = node
        self.put(at, 8, root)
        self.put(at + 8, 8, up)
        self.put(at + 0x10, 8, 1)

    def build_side(self, at, side, width):
        if side.hollow is not None:
            self.build_hollow(at, side.hollow[0], side.hollow[1])
            return
        if side.keys:
            self.build_tree(at, side.keys, SIDE_NODE, width, side.height, tempt=0x7654321)
        elif side.claimed is None:
            self.put(at, 8, 0)
            self.put(at + 8, 8, 0x4142)
            self.put(at + 0x10, 8, 0)
        if side.null_root:
            self.put(at, 8, 0)
        if side.claimed is not None:
            if not side.keys:
                self.build_tree(at, [0x7654321], SIDE_NODE, width)
            self.put(at + 0x10, 8, side.claimed)

    def build_book(self, base, book, position, width):
        memory = self.machine.memory
        memory.put_bytes(base, ramp(BOOK_STRIDE, position * 3 + 5))
        shared = self.built.get(id(book))
        if shared is None:
            self.build_side(base + 0x80, book.bid, width)
            self.build_side(base + 0x98, book.ask, width)
            self.built[id(book)] = base
        else:
            memory.copy(base + 0x80, shared + 0x80, 0x30)
        self.put(base + 0x78, 8, book.last)
        self.put(base + 0xB0, 8, position if book.index is None else book.index)

    def build(self, case):
        memory = self.machine.memory
        memory.reset(self.top)
        self.top = BUMP - HEAP_BASE
        self.bump = BUMP
        self.events = []
        self.live = {}
        self.built = {}
        self.case = case
        copy = self.copy
        ASSETS = self.alloc(ASSET_STRIDE * len(case.assets) + 8)
        STATES = self.alloc(STATE_STRIDE * len(case.states) + 8)
        PAIRS = self.alloc(PAIR_STRIDE * len(case.pairs) + 8)
        TOKENS = self.alloc(TOKEN_STRIDE * len(case.tokens) + 8)
        for index, value in enumerate(case.now):
            self.put(NOW + index * 4, 4, value)
        perp_books = self.alloc(BOOK_STRIDE * max(len(case.perps), 1))
        for index, book in enumerate(case.perps):
            self.build_book(perp_books + index * BOOK_STRIDE, book, index, case.width)
        memory.put_bytes(PERP_VEC, ramp(0x60, 11))
        self.put(PERP_VEC + 8, 8, perp_books)
        self.put(PERP_VEC + 0x10, 8, len(case.perps))
        self.put(EX + copy["perps"], 8, PERP_VEC)
        self.put(EX + copy["perps"] + 8, 8, 0 if case.no_perps else case.perp_vector)
        memory.put_bytes(META_VEC, ramp(0x300, 23))
        self.put(META_VEC + 8, 8, ASSETS)
        self.put(META_VEC + 0x10, 8, len(case.assets))
        self.put(META_VEC + 0x30, 8, case.dex)
        self.put(META_VEC + 0x68, 8, STATES)
        self.put(META_VEC + 0x70, 8, len(case.states))
        self.put(EX + copy["metas"], 8, META_VEC)
        self.put(EX + copy["metas"] + 8, 8, 0 if case.no_metas else case.meta_vector)
        if case.halted:
            self.build_tree(META_VEC + 0x270, sorted(case.halted), SET_NODE, 3)
        else:
            self.put(META_VEC + 0x270, 8, 0)
        for index, decimals in enumerate(case.assets):
            memory.put_bytes(ASSETS + index * ASSET_STRIDE, ramp(ASSET_STRIDE, index + 40))
            self.put(ASSETS + index * ASSET_STRIDE + 0x2A, 1, decimals)
        for index, price in enumerate(case.states):
            memory.put_bytes(STATES + index * STATE_STRIDE, ramp(STATE_STRIDE, index + 70))
            self.put(STATES + index * STATE_STRIDE + 0x20, 8, price)
        spot_books = self.alloc(BOOK_STRIDE * max(len(case.spots), 1))
        for index, book in enumerate(case.spots):
            self.build_book(spot_books + index * BOOK_STRIDE, book, index, case.width)
        self.put(EX + copy["spots"], 8, spot_books)
        self.put(EX + copy["spots"] + 8, 8, len(case.spots))
        self.put(EX + FIELD_PAIRS, 8, PAIRS)
        self.put(EX + FIELD_PAIRS + 8, 8, len(case.pairs))
        for index, (base, quote) in enumerate(case.pairs):
            memory.put_bytes(PAIRS + index * PAIR_STRIDE, ramp(PAIR_STRIDE, index + 90))
            self.put(PAIRS + index * PAIR_STRIDE, 8, base)
            self.put(PAIRS + index * PAIR_STRIDE + 8, 8, quote)
        self.put(EX + FIELD_TOKENS, 8, TOKENS)
        self.put(EX + FIELD_TOKENS + 8, 8, len(case.tokens))
        for index, (decimals, wei) in enumerate(case.tokens):
            memory.put_bytes(TOKENS + index * TOKEN_STRIDE, ramp(TOKEN_STRIDE, index + 130))
            self.put(TOKENS + index * TOKEN_STRIDE + 0x48, 1, decimals)
            self.put(TOKENS + index * TOKEN_STRIDE + 0x49, 1, wei)
        self.put(EX + copy["network"], 1, case.network)
        self.put(EX + copy["delay"] + 0x20, 8, case.bucket)
        self.put(EX + copy["delay"] + 0x28, 8, case.seen)
        self.top = self.bump - HEAP_BASE

    # stubs

    def from_entry(self, m):
        return self.entry_range[0] <= m.call_site < self.entry_range[1]

    def on_drop(self, m):
        self.events.append(("drop result", m.memory.read(m.regs[RDI], 2)))

    def on_alloc(self, m):
        size = m.regs[RDI]
        direct = self.from_entry(m)
        if direct:
            self.events.append(("alloc", size))
            if self.case.alloc_fails:
                m.regs[RAX] = 0
                return
        at = self.alloc(size)
        self.live[at] = size
        m.regs[RAX] = at

    def on_free(self, m):
        pointer, size = m.regs[RDI], m.regs[RSI]
        if self.live.pop(pointer, None) != size:
            raise Halt("free of a block that does not match: %#x %#x" % (pointer, size))
        if self.from_entry(m):
            if m.regs[RDX] & MASK[4]:
                raise Halt("free flag")
            self.events.append(("free", size))

    def on_grow(self, m):
        vec = m.regs[RDI]
        read = m.memory.read
        capacity, size = read(vec, 8), read(vec + 0x10, 8)
        if not capacity and read(vec + 8, 8) != 8:
            raise Halt("empty vector pointer")
        new = max(capacity * 2, 4)
        at = self.alloc(new * 8)
        self.live[at] = new * 8
        if capacity:
            pointer = read(vec + 8, 8)
            m.memory.copy(at, pointer, size * 8)
            self.live.pop(pointer)
        self.put(vec, 8, new)
        self.put(vec + 8, 8, at)

    def on_memcpy(self, m):
        if m.regs[RDX]:
            m.memory.copy(m.regs[RDI], m.regs[RSI], m.regs[RDX])
        m.regs[RAX] = m.regs[RDI]

    def on_outcome(self, m):
        if m.regs[RSI] != EX + FIELD_META:
            raise Halt("outcome lookup meta")
        value, byte = self.case.outcomes.get(m.regs[RDX], (0x5A5A5A5A5A5A5A5A, 2))
        self.put(m.regs[RDI], 8, value)
        self.put(m.regs[RDI] + 8, 1, byte)

    def on_sample(self, m):
        if m.regs[RDI] != EX + self.copy["delay"]:
            raise Halt("sample state")
        self.events.append(("sample", m.regs[RSI] & MASK[4], struct.pack("<Q", m.xmm[0] & MASK[8]).hex(), m.memory.bytes_at(m.regs[RDX], 12).hex()))

    def on_status(self, m):
        rec, network = m.regs[RDI], m.regs[RSI]
        read = m.memory.read
        if m.regs[RDX] != EX + self.copy["status_map"]:
            raise Halt("status map")
        self.events.append(("status step", read(rec, 8), read(rec + 8, 8), m.memory.bytes_at(rec + 0x10, 16).hex(), read(rec + 0x20, 1), read(network, 1)))

    def on_alloc_failed(self, m):
        raise Panicked(("alloc failed", m.regs[RDI], m.regs[RSI]))

    def on_panic(self, m):
        raise Panicked(("panic", m.regs[RDI]))

    def on_bounds(self, m):
        raise Panicked(("bounds", m.regs[RDI], m.regs[RSI], m.regs[RDX]))

    def on_mul(self, m):
        raise Panicked(("mul overflow", m.regs[RDI]))

    def on_add(self, m):
        raise Panicked(("add overflow", m.regs[RDI]))

    def on_sub(self, m):
        raise Panicked(("sub overflow", m.regs[RDI]))

    def on_unwrap(self, m):
        if m.regs[RSI] != 0x2B:
            raise Halt("unwrap text")
        raise Panicked(("unwrap", m.memory.read(m.regs[RDX], 2), m.regs[R8]))

    # runs

    def run(self, case):
        self.build(case)
        machine = self.machine
        result = {"stop": None, "events": self.events, "seen": None}
        try:
            if case.direct:
                book = self.machine.memory.read(EX + self.copy["spots"], 8)
                self.events.append(("fallback", machine.run(FALLBACK, {RDI: book})))
                result["seen"] = case.seen
                return result
            machine.run(self.copy["entry"], {RDI: EX, RSI: NOW})
        except Panicked as caught:
            result["stop"] = caught.args[0]
            result["seen"] = case.seen
            return result
        finally:
            self.top = max(self.top, self.bump - HEAP_BASE)
        if self.live:
            raise Halt("blocks still live")
        if machine.memory.read(EX + self.copy["delay"] + 0x20, 8) != case.bucket:
            raise Halt("bucket width changed")
        result["seen"] = machine.memory.read(EX + self.copy["delay"] + 0x28, 8)
        return result


CRASHES = (Halt, EvidenceError, IndexError, KeyError, ZeroDivisionError, StopIteration, OverflowError, ValueError, struct.error)


def compare_run(harness, case):
    try:
        actual = harness.run(case)
    except CRASHES as caught:
        return "%s: crash %s" % (case.label, caught)
    expected = spec_run(case, harness.copy)
    for key in ("stop", "events", "seen"):
        if actual.get(key) != expected.get(key):
            return "%s: %s differs: %s / %s" % (case.label, key, str(actual.get(key))[:300], str(expected.get(key))[:300])
    return None

# ---- cases ----

def lcg(state):
    return (state * 6364136223846793005 + 1442695040888963407) & MASK[8]


def wide(count, state=99):
    """Distinct books with odd, spread prices; every book has both sides."""
    rows = []
    for index in range(count):
        state = lcg(state)
        low = (state >> 24) | 1
        rows.append(Book([-(low + index)], [low + index + (state >> 60) + 1]))
    return rows


TOP = (1 << 64) - 1
INT_MIN = -(1 << 63)


def gate_cases():
    rows = [Case("no perp vector", no_perps=True), Case("no metadata vector", no_metas=True), Case("nothing listed"),
            Case("second perp vector entry ignored", perps=wide(1), perp_vector=3), Case("second metadata entry ignored", perps=wide(2), meta_vector=2),
            Case("first allocation fails", perps=wide(2), alloc_fails=True)]
    return rows


def mid_cases():
    rows = []
    pairs = ((-100, 100), (-101, 100), (-100, 103), (-1, 1), (-3, 4), (INT_MIN, INT_MIN), (INT_MIN, (1 << 63) - 1), (-(1 << 62), 1 << 62), (5, 9), (-7, -9), (0, 5), (-5, 0))
    for bid, ask in pairs:
        rows.append(Case("perp mid %d %d" % (bid, ask), perps=[Book([bid], [ask]), Book([-1000], [1002])], states=[33, 44]))
        rows.append(Case("spot mid %d %d" % (bid, ask), spots=[Book([bid], [ask], last=77)]))
    return rows


def fallback_cases():
    rows = [Case("perp one side empty, state price", perps=[Book([-10], []), Book([], [20]), Book()], states=[111, 222, 333], assets=[1, 2, 3]),
            Case("perp state price zero", perps=[Book()], states=[0]),
            Case("perp empty past the state rows", perps=[Book(), Book()], states=[5]),
            Case("perp with a mid needs no state row", perps=[Book([-10], [20])], states=[]),
            Case("perp empty, not halted", perps=[Book(), Book()], states=[5, 6], halted=(9,)),
            Case("perp empty, halted", perps=[Book(), Book()], states=[5, 6], halted=(1,)),
            Case("perp empty, halted under a dex", perps=[Book(), Book()], states=[5, 6], halted=(30001,), dex=3),
            Case("perp empty, several halted", perps=[Book() for _ in range(5)], states=[5, 6, 7, 8, 9], halted=(0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26)),
            Case("perp with a mid, halted", perps=[Book([-10], [20])], halted=(0,))]
    for bid, ask, last in ((0, 0, 5), (0, 0, 0), (7, 0, 3), (7, 0, 20), (7, 0, 0), (0, 9, 8), (5, 0, 5), (TOP >> 1, 0, TOP >> 1)):
        book = Book([bid] if bid else [], [ask] if ask else [], last=last)
        rows.append(Case("spot fallback %d %d %d" % (bid, ask, last), spots=[book]))
    other = Book([-40], [60], last=9)
    rows += [Case("spot index points at another book", spots=[Book([], [], index=1), other]),
             Case("spot empty book, index out of range", spots=[Book(index=3)]),
             Case("spot empty with a good top on its target", spots=[Book(index=1), Book([4], [], last=8)]),
             Case("spot with a mid, index out of the book vector", spots=[Book([-2], [4], index=3)], pairs=[(0, 1), (0, 1), (0, 1), (0, 2)], tokens=[(1, 3), (1, 4), (1, 5)])]
    return rows


def key_cases():
    rows = []
    for dex, count in ((1, 2), (2, 3), (9989, 2), (9990, 2), (9999, 1), (184467440737095, 1), (184467440737096, 1), (1844674407370955, 1), (1844674407370956, 1)):
        rows.append(Case("dex %d" % dex, perps=wide(count), dex=dex))
    rows.append(Case("dex top of u64 with a second book", perps=wide(3), dex=(TOP - 1) // 10000))
    rows.append(Case("key byte for wrong dex width", perps=wide(2), dex=1 << 40))
    return rows


def decimals_cases():
    rows = []
    for decimals in range(10):
        rows.append(Case("szDecimals %d" % decimals, perps=wide(2), assets=[decimals, 2], states=[1, 2]))
    rows.append(Case("szDecimals 0xff", perps=wide(1), assets=[0xFF]))
    rows.append(Case("more books than asset rows", perps=wide(3), assets=[1, 2], states=[1, 2, 3]))
    rows.append(Case("exactly as many asset rows", perps=wide(3), assets=[1, 2, 3], states=[1, 2]))
    tokens = [(0, 0), (2, 8), (3, 3), (6, 6), (1, 18), (9, 8), (0, 18), (3, 2)]
    for base, quote in ((1, 4), (1, 0), (2, 2), (5, 1), (0, 6), (3, 4), (2, 7), (7, 2), (1, 3), (6, 6)):
        rows.append(Case("spot pair %d %d" % (base, quote), spots=wide(1), pairs=[(base, quote)], tokens=tokens))
    rows += [Case("spot past the pairs", spots=wide(2), pairs=[(0, 1)]),
             Case("spot base past the tokens", spots=wide(1), pairs=[(3, 1)], tokens=[(1, 8), (1, 8), (1, 8)]),
             Case("spot quote past the tokens", spots=wide(1), pairs=[(1, 3)], tokens=[(1, 8), (1, 8), (1, 8)]),
             Case("spot last token", spots=wide(1), pairs=[(1, 2)], tokens=[(1, 8), (1, 8), (1, 8)])]
    return rows


def outcome_cases():
    rows = []
    for value, byte in ((0, 0), (0, 1), (3, 1), (7, 0), (419, 1), (419999000, 1), (419999029, 5), (419999029, 6), (419999030, 0), ((1 << 64) // 10, 0), ((1 << 64) // 10, 5), (1 << 61, 1), (TOP // 10 + 1, 1), (0xFFFFFFFFFA0A1EFF // 10, 5), (0xFFFFFFFFFA0A1F00 // 10, 0), (5, 2), (5, 3), (5, 0xFF)):
        rows.append(Case("outcome %d %d" % (value, byte), spots=wide(2), pairs=[(3, 1), (2, 1)], tokens=[(1, 8)] * 4, outcomes={3: (value, byte)}))
    rows.append(Case("two outcomes with one key", spots=wide(2), pairs=[(3, 1), (2, 1)], tokens=[(1, 8)] * 4, outcomes={3: (1 << 61, 0), 2: (1 << 62, 1)}))
    rows.append(Case("same index twice, later wins", spots=[Book([-10], [20], index=1), Book([-30], [40])]))
    return rows


def map_cases():
    rows = []
    for count in (10, 11, 12, 13, 23, 24, 40, 70, 134):
        rows.append(Case("%d perps" % count, perps=wide(count)))
    rows.append(Case("perps and spots", perps=wide(14), spots=wide(14, 7)))
    rows.append(Case("spots out of order", spots=[Book([-(index + 2)], [index + 9], index=(index * 7) % 20) for index in range(20)]))
    return rows


def time_cases():
    rows = []
    dates = ((1970, 1, 0, 0), (1970, 1, 5, 7000000), (1970, 1, 0, 999999), (1970, 2, 0, 0), (1969, 365, 86399, 999000000), (1969, 365, 86399, 1999000000), (2024, 366, 86399, 999999999), (2026, 303, 3600, 1500000000), (2101, 1, 0, 0),
             (2100, 365, 1, 0), (2000, 366, 2, 0), (1900, 365, 3, 0), (1600, 1, 4, 0), (1, 1, 5, 0), (0, 1, 0, 0), (-1, 1, 0, 0), (-399, 1, 0, 0), (-400, 1, 0, 0), (-401, 1, 0, 0), (-800, 366, 7, 0), (262000, 200, 8, 0), (-262000, 200, 9, 0))
    for year, ordinal, seconds, nanos in dates:
        rows.append(Case("time %d %d %d %d" % (year, ordinal, seconds, nanos), now=(pack_date(year, ordinal, 7), seconds, nanos), bucket=1))
    rows += [Case("bucket not reached", seen=1 << 62), Case("bucket equal", now=(pack_date(2026, 303), 0, 0), bucket=1000, seen=unix_millis((pack_date(2026, 303), 0, 0)) // 1000),
             Case("bucket one below", now=(pack_date(2026, 303), 0, 0), bucket=1000, seen=unix_millis((pack_date(2026, 303), 0, 0)) // 1000 - 1),
             Case("bucket one above", now=(pack_date(2026, 303), 0, 0), bucket=1000, seen=unix_millis((pack_date(2026, 303), 0, 0)) // 1000 + 1),
             Case("small pair, 32-bit divide", now=(pack_date(1970, 2), 1, 0), bucket=7, seen=0), Case("small pair, 32-bit divide, not reached", now=(pack_date(1970, 2), 1, 0), bucket=7, seen=1 << 40),
             Case("small pair, equal", now=(pack_date(1970, 1), 0, 7000000), bucket=7, seen=1), Case("wide width, small time", now=(pack_date(1970, 2), 1, 0), bucket=1 << 33, seen=0),
             Case("width exactly 2^32", now=(pack_date(1970, 2), 1, 0), bucket=1 << 32, seen=0), Case("time just over 2^32", now=(pack_date(1970, 50), 62296, 0), bucket=9, seen=0),
             Case("wide time, small width", bucket=3, seen=5), Case("network 0", network=0), Case("network 2", network=2), Case("sampled and bucketed", perps=wide(2), spots=wide(2), bucket=1, seen=5)]
    return rows


def tree_cases():
    rows = []
    for height in (1, 2, 3, 7, 8, 9, 10, 15, 16, 17):
        rows.append(Case("bid tree height %d" % height, perps=[Book(Side([-100, -90], height=height), [101])]))
        rows.append(Case("ask tree height %d" % height, spots=[Book([-100], Side([101, 120], height=height))]))
        rows.append(Case("spot fallback tree height %d" % height, spots=[Book(Side([-100], height=height), [], last=70)]))
        rows.append(Case("bid spine height %d" % height, perps=[Book(Side([-100], height=height), [101])]))
        rows.append(Case("ask spine height %d" % height, perps=[Book([-100], Side([101], height=height))]))
    for up in (1, 2, 3):
        rows.append(Case("hollow bid leaf up %d" % up, perps=[Book(Side(hollow=(up, -55)), [60])]))
        rows.append(Case("hollow ask leaf up %d" % up, perps=[Book([-50], Side(hollow=(up, 66)))]))
        rows.append(Case("hollow spot bid up %d" % up, spots=[Book(Side(hollow=(up, -55)), [60])]))
        rows.append(Case("hollow spot ask up %d" % up, spots=[Book([-50], Side(hollow=(up, 66)))]))
        rows.append(Case("hollow fallback bid up %d" % up, spots=[Book(Side(hollow=(up, -55)), [], last=2)]))
        rows.append(Case("hollow fallback ask up %d" % up, spots=[Book([], Side(hollow=(up, 66)), last=2)]))
    for up in (0, 2):
        rows.append(Case("hollow bid with nothing above %d" % up, perps=[Book(Side(hollow=(up, None)), [60])]))
        rows.append(Case("hollow ask with nothing above %d" % up, perps=[Book([-50], Side(hollow=(up, None)))]))
        rows.append(Case("hollow spot bid with nothing above %d" % up, spots=[Book(Side(hollow=(up, None)), [60])]))
        rows.append(Case("hollow spot ask with nothing above %d" % up, spots=[Book([-50], Side(hollow=(up, None)))]))
        rows.append(Case("hollow fallback bid with nothing above %d" % up, spots=[Book(Side(hollow=(up, None)), [], last=2)]))
    rows += [Case("root present, length 0", perps=[Book(Side(claimed=0), [60])]), Case("ask root present, length 0", spots=[Book([-50], Side(claimed=0), last=4)]),
             Case("root null, length nonzero", perps=[Book(Side([-9], null_root=True), [60])]), Case("ask root null, length nonzero", spots=[Book([-50], Side([9], null_root=True), last=4)]),
             Case("many keys in a tree", perps=[Book(list(range(-300, -240)), list(range(301, 340)))], width=2)]
    return rows


def direct_cases():
    rows = []
    for bid, ask, last in ((3, 5, 4), (3, 4, 5), (4, 3, 5), (4, 5, 3), (5, 3, 4), (5, 4, 3), (3, 3, 3), (3, 3, 9), (9, 3, 3), (3, 9, 3), (1 << 63, 1 << 62, 7), (TOP >> 1, 5, 0), (5, 9, 0), (9, 5, 0), (0, 0, 8), (0, 8, 0), (8, 0, 0), (0, 0, 0)):
        rows.append(Case("direct fallback %d %d %d" % (bid, ask, last), spots=[Book([bid] if bid else [], [ask] if ask else [], last=last)], direct=True))
    return rows


def all_cases():
    return direct_cases() + gate_cases() + mid_cases() + fallback_cases() + key_cases() + decimals_cases() + outcome_cases() + map_cases() + time_cases() + tree_cases()

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


def pin_rows():
    rows = []
    for copy in COPIES:
        entry = copy["entry"]
        rows += [(entry, "mov word [rsp+0x38], 0x141: the error built for both first-entry reads", b"\x66\xc7\x44\x24\x38\x41\x01", 4),
                 (entry, "mov ecx, 0x2710: asset key step", b"\xb9\x10\x27\x00\x00", 1),
                 (entry, "cmp rcx, 0x270f: plain key limit", b"\x48\x81\xf9\x0f\x27\x00\x00", 1),
                 (entry, "cmp rcx, 0x5f45a5f: last key that takes the dex shift", b"\x48\x81\xf9\x5f\x5a\xf4\x05", 1),
                 (entry, "lea esi, [rcx+0x186a0]: dex shift 100000", b"\x8d\xb1\xa0\x86\x01\x00", 1),
                 (entry, "cmp rax, 7: szDecimals above 6 panics", b"\x48\x83\xf8\x07", 1),
                 (entry, "mov ecx, 6: the perp scale is 10^(6 - szDecimals)", b"\xb9\x06\x00\x00\x00", 1),
                 (entry, "mov edi, 1: spot arm of the key encoder, and the year arm of the time conversion", b"\xbf\x01\x00\x00\x00", 2),
                 (entry, "mov qword [rsp+0x40], 0x19: length of the status text", b"\x48\xc7\x44\x24\x40\x19\x00\x00\x00", 1),
                 (entry, "add rbx, status map: argument of the status step", b"\x48\x81\xc3" + struct.pack("<I", copy["status_map"]), 1)]
    rows += [(FALLBACK, "mov rbx, [rbx+0x78]: stored last price, always the last value of the list", b"\x48\x8b\x5b\x78", 1),
             (FALLBACK, "cmovne rbx, r15: median if nonzero, else the last price", b"\x49\x0f\x45\xdf", 1),
             (STATUS_STEP, "cmp bl, 1: nothing runs below this flag", b"\x80\xfb\x01", 1)]
    return rows


def read_pins(image):
    rows = []
    for start, meaning, pattern, expected in pin_rows():
        found = find_all(image, start, pattern)
        if len(found) != expected:
            raise EvidenceError("pin %r at %#x has %d sites" % (meaning, start, len(found)))
        rows.append({"function": "%#x" % start, "sites": ["%#x" % va for va in found], "bytes": pattern.hex(), "meaning": meaning})
    return rows


def read_text(image, va, text):
    data = bytes(image.blob[image.offset(va):image.offset(va) + len(text)])
    if data != text:
        raise EvidenceError("text at %#x differs" % va)
    return {"va": "%#x" % va, "bytes": text.decode("ascii")}


def read_constants(image):
    limits = struct.unpack_from("<dd", image.blob, image.offset(TIMER_LIMITS))
    if limits != (0.01, 0.05):
        raise EvidenceError("status step pair differs")
    powers = {}
    for copy in COPIES:
        values = struct.unpack_from("<23d", image.blob, image.offset(copy["powers"]))
        if values != tuple(power(exponent) for exponent in range(23)):
            raise EvidenceError("power table at %#x differs" % copy["powers"])
        powers["%#x" % copy["powers"]] = 23
    return {"status_text": read_text(image, STATUS_NAME, STATUS_TEXT), "sample_text": read_text(image, SAMPLE_NAME, SAMPLE_TEXT),
            "status_pair": {"va": "%#x" % TIMER_LIMITS, "values": list(limits)}, "power_tables_checked_rows": powers}


def call_targets(image, start):
    """Direct call targets of one function, read through the byte decoder."""
    found = []
    for row in decode_range(image, *image.exact_fde(start)):
        if row.op == "call" and row.target and row.target not in found:
            found.append(row.target)
    return found


def check_edges(image):
    """Each edge of each copy is a direct call in the function that the copy table says."""
    rows = []
    for copy in COPIES:
        wanted = [RESULT_DROP, copy["top_perp"], copy["top_spot"], FALLBACK, SPOT_KEY, copy["insert"], copy["drain"], STATUS_STEP]
        calls = call_targets(image, copy["entry"])
        missing = [target for target in wanted if target not in calls]
        if missing:
            raise EvidenceError("%#x misses %s" % (copy["entry"], [hex(value) for value in missing]))
        rows.append({"copy": copy["name"], "function": "%#x" % copy["entry"], "targets": ["%#x" % value for value in wanted]})
    calls = call_targets(image, FALLBACK)
    if any(target not in calls for target in (FALLBACK_TOP, COLLECT, MEDIAN)):
        raise EvidenceError("%#x edges" % FALLBACK)
    rows.append({"copy": "shared", "function": "%#x" % FALLBACK, "targets": ["%#x" % value for value in (FALLBACK_TOP, COLLECT, MEDIAN)]})
    # The status step has a lock prefix that the decoder does not take, so its one call is read as rel32 bytes.
    data = bytes(image.blob[image.offset(STATUS_CALL):image.offset(STATUS_CALL) + 5])
    if data[0] != 0xE8 or STATUS_CALL + 5 + struct.unpack_from("<i", data, 1)[0] != STATUS_BODY or image.fde(STATUS_CALL)[0] != STATUS_STEP:
        raise EvidenceError("status step call")
    rows.append({"copy": "shared", "function": "%#x" % STATUS_STEP, "targets": ["%#x" % STATUS_BODY]})
    return rows


def read_hosts(image):
    """The single direct caller of each copy, its host, and the host's single caller."""
    rows = []
    sites = direct_sites(image, [row[0] for row in HOSTS] + [row[2] for row in HOSTS])
    for entry, site, host, outer_site, outer in HOSTS:
        if [row[0] for row in sites[entry]] != [site] or [row[0] for row in sites[host]] != [outer_site]:
            raise EvidenceError("call sites of %#x" % entry)
        if image.fde(site)[0] != host or image.fde(outer_site)[0] != outer:
            raise EvidenceError("host of %#x" % entry)
        rows.append({"copy": "%#x" % entry, "site": "%#x" % site, "host": "%#x" % host, "host_site": "%#x" % outer_site, "outer": "%#x" % outer})
    return rows


def copy_diff(image):
    """Instruction pairs of each copy against the first: same shape, and what differs."""
    base = decode_range(image, *image.exact_fde(FIRST["entry"]))
    rows = []
    for copy in COPIES[1:]:
        other = decode_range(image, *image.exact_fde(copy["entry"]))
        if len(other) != len(base):
            raise EvidenceError("copy length")
        shape = 0
        fields = {}
        for left, right in zip(base, other):
            if left.op != right.op or left.size != right.size or left.cc != right.cc or (left.imm_at is not None and left.op == "mov" and left.a != right.a):
                shape += 1
            for one, two in ((left.a, right.a), (left.b, right.b)):
                if one and two and one[0] == "m" and one[1] not in (None, RSP) and one[4] != two[4]:
                    fields["%#x" % one[4]] = "%#x" % two[4]
        rows.append({"copy": copy["name"], "instructions": len(other), "shape_differences": shape, "field_map": dict(sorted(fields.items()))})
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


MUTATED = ((FIRST["entry"], "sampler"), (FIRST["top_perp"], "perp top reader"), (FALLBACK, "spot price fallback"), (COLLECT, "fallback list"), (MEDIAN, "median"))


def run_mutants(image, seen, verbose=False):
    results = []
    harness = Harness(image)
    machine = harness.machine
    machine.step_limit = MUTANT_STEP_LIMIT
    ordered = sorted(all_cases(), key=Case.size)
    for start, _ in MUTATED:
        cases = list(ordered)
        rows = decode_range(image, *image.exact_fde(start))
        for va, at, kind in mutation_targets(image, rows):
            if va not in seen:
                results.append({"function": start, "va": va, "kind": kind, "result": "unreached", "by": ""})
                continue
            machine.patches = mutate_patch(image, va, at, kind)
            machine.cache.pop(va, None)
            failed = None
            for index, case in enumerate(cases):
                failed = compare_run(harness, case)
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

EXCHANGE_MAP = (
    (0x90, "spot metadata base passed to the key encoder; pairs and tokens below are read through it"),
    (0x1F8, "spot pairs: pointer, then length at +0x200; stride 0x20, base token +0x00, quote token +0x08"),
    (0x210, "tokens: pointer, then length at +0x218; stride 0xe8, szDecimals byte +0x48, weiDecimals byte +0x49"),
    (0x5C0, "perp metadata vector: pointer, length at +0x5c8; only the first entry is read"),
    (0x8F2, "network byte, handed to the status step"),
    (0x3370, "perp book collections: pointer, length at +0x3378; only the first entry is read"),
    (0x3388, "spot books: pointer, length at +0x3390; stride 0xd8"),
    (0x31B8, "delay state handed to the sample writer"),
    (0x31D8, "bucket width in milliseconds, read and never written; no zero check before the divide"),
    (0x31E0, "largest bucket seen, raised here"),
    (0x3228, "map handed to the status step"),
)
METADATA_MAP = (
    (0x08, "asset rows: pointer, length at +0x10; stride 0x30, szDecimals byte +0x2a"),
    (0x30, "dex index"),
    (0x68, "oracle rows: pointer, length at +0x70; stride 0x60, price word +0x20; the bound panic is l1/src/clearinghouse/oracle/oracle.rs:197:18"),
    (0x270, "u64 set: root, height at +0x278; keys at node +0x08, length at node +0x62, edges at node +0x68"),
)
BOOK_MAP = (
    (0x78, "last price word, the third input of the spot fallback"),
    (0x80, "bid tree: root, height, length"),
    (0x98, "ask tree: root, height, length"),
    (0xB0, "spot index of the book"),
)
REFERENCE_CLAIMS = (
    {"reference": "l1/books.rs:342-357", "claim": "0x4CDF580 is recompute_volume_accumulator: sums mid * resting size into a u128 and counts active books",
     "bytes": "no size is read, no sum or count is kept, and nothing is stored but the bucket word. Each price goes to the sample writer 0x392b930 through slot 0x57748d8"},
    {"reference": "l1/time.rs:392", "claim": "record_mark_price_sample_and_update_action_delay takes a LocalAssetIndex and a mark price, and has no caller in the reference",
     "bytes": "slot 0x57748d8 holds 0x392b930 and these three loops are its callers. The key is the wire asset id, 10000 + spot for a spot, and the price is the book mean with a fallback, not a mark price"},
    {"reference": "l1/books.rs:359-365", "claim": "iter_all_books chains main perp, perp dex and spot collections",
     "bytes": "the sampler reads the first perp collection and the spot books only. A second collection is never touched, proved by run with vectors of length 3 and 2"},
)
UNREACHABLE_SECOND_BOUND = "second bound check of the spot index: the key encoder has already panicked on the same index and length"
NOT_REACHED = "no case reaches it"
LANDING = "unwind landing pad or panic tail: no case unwinds"
HALT_WALK = "walk of the set at metadata +0x270: every exit joins at 0x4cdf6f4 with rdi unchanged, so the walk's result is never read"
BACK_HANDLE = "back handle of the map iterator: the drain only walks forward"
YEAR_ZERO = "year <= 0 arm of the time conversion: every such time clamps to 0, so this value never shows"
SHIFT_SIGN = "sign fix of a division of the shifted year, which is never negative"
HEIGHT_EIGHT = "reached only with the low three bits of the height nonzero, so height 8 never arrives and 8 and 9 compare alike"
LIST_SHORT = "the fallback list has at most 3 values, so the insertion sort path always runs and the 21-value limit never shows"
TAG_BYTE = "tag byte of the fallback array: the collector reads only the value word, and 0 means nothing"
START_ZERO = "start of the iterator, 0 at the only call"
CONSUMED = "copy of array entry 0, which is already consumed when the copy is made"
EMPTY_POINTER = "dangling pointer of an empty vector: length 0 means nothing reads it"
TWO_ENTRIES = "the fallback array has two entries, so this value for a third is never used"
NEVER_FULL = "growth of a list of capacity 4 that holds at most 2 here"
NEVER_EMPTY = "the fallback list always holds at least the last word"
PLAIN_LIMIT = "both sides of this limit need offset 9999 in the book vector, so 10000 books, more than a case holds"
COUNTER = "counter overflow at u64 max: needs 2^64 books"
DEAD_BYTES = "bytes of a dead store"


def reason_for(row):
    if row["result"] == "killed":
        return ""
    va = row["va"]
    for low, high, reason in REASON_RANGES:
        if low <= va < high:
            return reason
    return REASONS.get(va, "")


def outcome_name(spec):
    if spec["stop"]:
        return "panic %s" % spec["stop"][0]
    samples = sum(1 for event in spec["events"] if event[0] == "sample")
    return "%s samples" % ("no" if not samples else "some")


def worked_run(harness):
    """One perp with a mid, one with only the state price, one spot with a mid, one on its fallback."""
    case = Case("worked", perps=[Book([-1999], [2002]), Book()], assets=[2, 1], states=[1000, 2500],
                spots=[Book([-120], [130]), Book([-90], [], last=70)], pairs=[(1, 0), (2, 0)], tokens=[(6, 8), (2, 8), (5, 8)], bucket=60000)
    run = harness.run(case)
    rows = []
    for event in run["events"]:
        if event[0] == "sample":
            rows.append({"key": event[1], "price": struct.unpack("<d", bytes.fromhex(event[2]))[0]})
    return {"perp_books": [{"bid": 1999, "ask": 2002, "szDecimals": 2}, {"bid": 0, "ask": 0, "state_price": 2500, "szDecimals": 1}],
            "spot_books": [{"bid": 120, "ask": 130, "quote_wei": 8, "base_sz": 2}, {"bid": 90, "ask": 0, "last": 70, "quote_wei": 8, "base_sz": 5}],
            "samples_in_order": rows, "status_flag": [event for event in run["events"] if event[0] == "status step"][0][4]}


def analyse(image, full=True, verbose=False):
    cases = all_cases()
    harnesses = [Harness(image, copy) for copy in COPIES]
    mismatches = []
    outcomes = {}
    for harness in harnesses:
        for case in cases:
            trouble = compare_run(harness, case)
            if trouble:
                mismatches.append("%s %s" % (harness.copy["name"], trouble))
    for case in cases:
        name = outcome_name(spec_run(case))
        outcomes[name] = outcomes.get(name, 0) + 1
    worked = worked_run(harnesses[0])
    seen = set()
    for harness in harnesses:
        seen |= harness.machine.seen
    first_seen = set(harnesses[0].machine.seen)
    steps = sum(harness.machine.steps for harness in harnesses)
    functions = []
    done = set()
    named = [("entry", copy["entry"], copy["name"]) for copy in COPIES] + [("top reader", value, "shared") for value in sorted({copy["top_perp"] for copy in COPIES} | {copy["top_spot"] for copy in COPIES} | {FALLBACK_TOP})]
    named += [("spot fallback", FALLBACK, "shared"), ("fallback list", COLLECT, "shared"), ("median", MEDIAN, "shared"), ("spot key encoder", SPOT_KEY, "shared")]
    named += [("map insert", value, "copy") for value in sorted({copy["insert"] for copy in COPIES})] + [("map drain", value, "copy") for value in sorted({copy["drain"] for copy in COPIES})]
    for role, start, owner in named:
        if start in done:
            continue
        done.add(start)
        begin, end = image.exact_fde(start)
        rows = decode_range(image, begin, end)
        functions.append({"role": role, "owner": owner, "start": "%#x" % begin, "end": "%#x" % end, "size": end - begin, "instructions": len(rows),
                          "instructions_stepped": sum(1 for row_ in rows if row_.va in seen)})
    relative = harnesses[0].relative
    targets = sorted({copy["entry"] for copy in COPIES} | {FALLBACK, SAMPLE_WRITER, STATUS_STEP})
    sites = direct_sites(image, targets)
    site_rows = []
    for target in sorted(sites):
        for va, opcode in sorted(sites[target]):
            site_rows.append((target, va, opcode, image.fde(va)[0], image.fde(va)[1]))
    results_rows = run_mutants(image, first_seen, verbose) if full else []
    tally = {key: sum(1 for row_ in results_rows if row_["result"] == key) for key in ("killed", "survived", "unreached")}
    locations = [{"slot": "%#x" % slot, "name": name, "path": image.location(slot, relative)[0], "line": image.location(slot, relative)[1],
                  "column": image.location(slot, relative)[2]} for slot, name in sorted(LOCATION_NAMES.items())]
    for copy in COPIES:
        for key, name in (("loc_counter", "asset counter"), ("loc_spot", "spot book by index"), ("loc_math", "dex * 10000 + offset"), ("loc_state", "oracle row by asset")):
            slot = copy[key]
            locations.append({"slot": "%#x" % slot, "name": "%s, %s copy" % (name, copy["name"]), "path": image.location(slot, relative)[0], "line": image.location(slot, relative)[1],
                              "column": image.location(slot, relative)[2]})
    return {
        "target": {"file": "artifacts/node/94/hl-node", "sha256": SHA256},
        "functions": functions,
        "hosts": read_hosts(image),
        "edges": check_edges(image),
        "copies": [{key: ("%#x" % value if isinstance(value, int) else value) for key, value in copy.items()} for copy in COPIES],
        "copy_diff": copy_diff(image),
        "constants": read_constants(image),
        "slots": {"%#x" % slot: {"target": "%#x" % relative[slot] if slot in relative else "dynamic symbol", "meaning": SLOT_NAMES[slot]} for slot in sorted(SLOT_NAMES)},
        "pins": read_pins(image),
        "locations": locations,
        "exchange_fields": [{"offset": "%#x" % offset, "meaning": meaning} for offset, meaning in EXCHANGE_MAP],
        "metadata_fields": [{"offset": "%#x" % offset, "meaning": meaning} for offset, meaning in METADATA_MAP],
        "book_fields": [{"offset": "%#x" % offset, "meaning": meaning} for offset, meaning in BOOK_MAP],
        "side_node": SIDE_NODE,
        "set_node": SET_NODE,
        "map_leaf_size": MAP_LEAF,
        "worked_example": worked,
        "reference_claims": list(REFERENCE_CLAIMS),
        "cases": {"total": len(cases), "per_copy": len(cases)},
        "outcomes": dict(sorted(outcomes.items())),
        "mismatches": len(mismatches),
        "first_mismatch": mismatches[0] if mismatches else "",
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
    lines += ["%#x\t%#x\t%#x\t%#x\t%#x" % row_ for row_ in sites]
    files["call_sites.tsv"] = "\n".join(lines) + "\n"
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


REASON_RANGES = ((0x4CDF811, 0x4CDF892, HALT_WALK), (0x4CDFB29, 0x4CDFB4E, YEAR_ZERO), (0x4CDFD54, 0x4CDFDF7, LANDING), (0x4CDFC47, 0x4CDFD54, LANDING),
                 (0x3278191, 0x32781B7, LANDING), (0x3BD55A0, 0x3BD55BC, NEVER_FULL), (0x3BD55E5, 0x3BD561A, LANDING), (0x359CAE6, 0x359CAFA, NEVER_EMPTY), (0x359CB5D, 0x359CB7C, LANDING), (0x359CBBC, 0x359CBD5, LANDING))
REASONS = {0x4CDF68C: EMPTY_POINTER, 0x4CDF6F4: PLAIN_LIMIT, 0x4CDF715: PLAIN_LIMIT, 0x4CDF967: UNREACHABLE_SECOND_BOUND, 0x4CDFA53: BACK_HANDLE, 0x4CDFB6F: SHIFT_SIGN,
           0x3C18BC5: HEIGHT_EIGHT, 0x3C18CA5: HEIGHT_EIGHT, 0x327810C: TAG_BYTE, 0x3278116: TAG_BYTE, 0x3BD548E: START_ZERO, 0x3BD54ED: CONSUMED, 0x359CB09: LIST_SHORT, 0x3BD558B: TWO_ENTRIES, 0x3BD55C9: TWO_ENTRIES}

if __name__ == "__main__":
    sys.exit(main())
