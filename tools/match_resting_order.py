#!/usr/bin/env python3
"""Pin the node #94 one-resting-order match step from ELF bytes.

Three FDEs of one shape take a taker record, a resting slab slot and a budget, and return a
fill or a no-fill result. Their bytes run in a Python evaluator with stubbed callees, and an
independently written specification predicts every result field and every callee argument.
Every conditional is then flipped and every immediate perturbed to show the run can tell.
No objdump or readelf output is parsed and the binary is never executed. Standard library only.
"""

import argparse
import bisect
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"

# name, start, (books ptr, books len, table, flag) offsets on the context, leg builder, Location slot
COPIES = (
    ("a", 0x431C530, (0x1040, 0x1048, 0x1050, 0x1372), 0x49E3D20, 0x571CA38),
    ("b", 0x431D020, (0x5C0, 0x5C8, 0x5D0, 0x8F2), 0x49E4450, 0x571CA38),
    ("c", 0x26EFF10, (0x5C0, 0x5C8, 0x5D0, 0x8F2), 0x232D590, 0x56BD8A0),
)
BODY_SIZE = 0xAED
MASK_FN = 0x3711BA0
MASK_LEG = 0x3BFCDC0
DROP = 0x3379490
LOOKUP = 0x36F57F0
CAP_FN = 0x370AFD0
MARGIN_FN = 0x37130B0
PRED_FN = 0x37E4FB0
GOT_PRED = 0x5773228
GOT_MARGIN = 0x5774890
GOT_CAP = 0x5774898
GOT_MASK = 0x5774558
GOT_MEMCPY = 0x576DFE0
GOT_PANIC = 0x576E470
GOT_UNWRAP = 0x576E048
GOT_ONCE = 0x576E8B8
GOT_BOUNDS = 0x576DFC8
GOT_NOUNWIND = 0x576E128
GOT_NAMES = {GOT_PRED: "user predicate", GOT_MARGIN: "margin record", GOT_CAP: "size cap", GOT_MASK: "fill mask",
             GOT_PANIC: "panic with Location", GOT_UNWRAP: "unwrap failed", GOT_ONCE: "once call",
             GOT_NOUNWIND: "cannot unwind"}
ONCE_STATE = 0x577AB98
UNWRAP_TEXT = 0x58C079
UNWRAP_LOCATION = 0x56E9AE0
UNWRAP_VTABLE = 0x56E9F10
MASK_LOCATION = 0x56F1CB0
DIVISOR = 1e9
ZERO16 = 0x207DA0
DOUBLE_1E9 = 0x20A220
STATUS_TABLE = 0x5A572C
STATUS_TABLE_ARMS = (0x3A008E0, 0x3A00C66)
STATUS_ARM = bytes.fromhex("488b3e488b4608488b4018488d35")
NONE_WORD = 0x8000000000000018
WORD_MARGIN = 0x8000000000000003
WORD_POSITION = 0x8000000000000004
MAX_NOTIONAL = 0x7FFFFFFFFFFFFFFE
NO_FILL = 2
# Bytes of the fill record with a defined value; the last three of 0x238 are padding.
FILL_BYTES = 0x235
# Offsets from each copy's start of the instruction that stores the reason byte.
EXITS = (
    ("self_cross", 0x1A2, "same 20-byte user, or the predicate holds for both users"),
    ("zero_budget", 0x1D1, "budget is 0"),
    ("reduce_only_block", 0x651, "reduce-only slot: no position entry, position 0 or position on the wrong side"),
    ("empty_slot", 0x6B6, "usable resting size is 0"),
    ("maker_cap_zero", 0x96C, "first cap call returned 0"),
    ("taker_cap_zero", 0x9C9, "second cap call returned 0"),
    ("mask_maker", 0xA3C, "fill mask: the maker leg bit is clear"),
    ("mask_taker", 0xA3C, "fill mask: the maker bit is set and the taker bit is clear"),
    ("fill", 0x9C9, "both mask bits set"),
)
# Bytes that must sit at a fixed offset of each leg builder.
LEG_PINS = (
    (0xEC, "4038a8c2000000", "leg index compared with slot +0xc2"),
    (0x21, "b914000000", "second user of the pair is 0x14 bytes in"),
    (0x247, "48c70301000000", "result tag is written as 1"),
)

# Mutants that cannot change a defined output, by address in copy a.
SURVIVOR_NOTES = {
    0x431CB5E: "copy length of undefined bytes on a no-fill exit; the extra byte is overwritten by the status",
    0x431CD98: "copy length; the extra byte is overwritten by the price field",
    0x431CE2B: "copy length; the extra byte lands in scratch space",
    0x431CE58: "copy length; the extra byte is overwritten by the status",
    0x431CED8: "copy length of undefined bytes on a no-fill exit; the extra byte is overwritten by the status",
    0x431CF0D: "second test of a bit already known to be clear after the both-bits check",
    0x431CF4E: "copy length of undefined bytes on a no-fill exit; the extra byte is overwritten by the status",
}
UNREACHED_NOTES = {
    0x431CF12: "the mov of tag 2 behind the second bit test, which never passes",
}

# Tail of the size cap: rdx keeps r15, rax is the min with the other value when bit 0 of a stack flag is set.
CAP_TAIL = (0x370BEFB, "4c39f8490f43c7f684245001000001490f44c74c89fa")

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RCX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x4000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x8000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 20000

CTX = HEAP_BASE
BOOKS = HEAP_BASE + 0x1400
ENTRY_STRIDE = 0x2F0
OUT = HEAP_BASE + 0x2000
SLOT = HEAP_BASE + 0x2400
TAKER = HEAP_BASE + 0x2600
ENTRY = HEAP_BASE + 0x2700
NODES = HEAP_BASE + 0x3000
NODE_SIZE = 0x400
TABLE = HEAP_BASE + 0x6000


class EvidenceError(Exception):
    pass


class Halt(Exception):
    pass


class Panicked(Exception):
    pass


class Image:
    """Parsed section, segment and unwind tables of one ELF byte string."""

    def __init__(self, blob):
        self.blob = blob
        if blob[:5] != b"\x7fELF\x02" or struct.unpack_from("<H", blob, 18)[0] != 62:
            raise EvidenceError("not an x86-64 ELF")
        phoff, shoff = struct.unpack_from("<QQ", blob, 32)
        phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHH", blob, 56)
        self.loads = []
        for index in range(phnum):
            kind, _, offset, vaddr, _, filesz, _, _ = struct.unpack_from("<IIQQQQQQ", blob, phoff + 56 * index)
            if kind == 1:
                self.loads.append((vaddr, offset, filesz))
        rows = [struct.unpack_from("<IIQQQQIIQQ", blob, shoff + shentsize * i) for i in range(shnum)]
        names = rows[shstrndx][4]
        self.sections = {}
        for row in rows:
            end = blob.index(b"\0", names + row[0])
            self.sections[bytes(blob[names + row[0]:end]).decode()] = {"addr": row[3], "offset": row[4], "size": row[5]}
        self.text = self.sections[".text"]
        self.starts, self.fdes = self.fde_table()

    def fde_table(self):
        hdr = self.sections[".eh_frame_hdr"]
        base = hdr["offset"]
        if bytes(self.blob[base:base + 4]) != b"\x01\x1b\x03\x3b":
            raise EvidenceError("unexpected .eh_frame_hdr encoding")
        count = struct.unpack_from("<I", self.blob, base + 8)[0]
        pairs = [struct.unpack_from("<ii", self.blob, base + 12 + 8 * i) for i in range(count)]
        starts = [hdr["addr"] + start for start, _ in pairs]
        if starts != sorted(starts):
            raise EvidenceError("unsorted .eh_frame_hdr table")
        return starts, [hdr["addr"] + fde for _, fde in pairs]

    def offset(self, va):
        for vaddr, offset, filesz in self.loads:
            if vaddr <= va < vaddr + filesz:
                return va - vaddr + offset
        raise EvidenceError("address outside file-backed segments: %#x" % va)

    def fde(self, va):
        """Return (start, end) of the FDE whose half-open range contains va."""
        index = bisect.bisect_right(self.starts, va) - 1
        if index < 0:
            raise EvidenceError("address before every FDE: %#x" % va)
        at = self.offset(self.fdes[index])
        length, _, begin, size = struct.unpack_from("<IIiI", self.blob, at)
        if length == 0xFFFFFFFF:
            raise EvidenceError("64-bit FDE length is not supported")
        start = self.fdes[index] + 8 + begin
        if start != self.starts[index]:
            raise EvidenceError("FDE start disagrees with the search table: %#x" % va)
        if not start <= va < start + size:
            raise EvidenceError("address outside every FDE: %#x" % va)
        return start, start + size

    def exact_fde(self, va):
        start, end = self.fde(va)
        if start != va:
            raise EvidenceError("not an FDE start: %#x" % va)
        return start, end

    def relative_slots(self):
        """Map every R_X86_64_RELATIVE slot to its addend."""
        rela = self.sections[".rela.dyn"]
        found = {}
        for at in range(rela["offset"], rela["offset"] + rela["size"], 24):
            slot, info, addend = struct.unpack_from("<QQq", self.blob, at)
            if info & 0xFFFFFFFF == 8:
                found[slot] = addend
        return found

    def location(self, slot, relative):
        """Decode one Location record; the path is kept only below the crate root."""
        size, line, column = struct.unpack_from("<QII", self.blob, self.offset(slot) + 8)
        start = self.offset(relative[slot])
        path = bytes(self.blob[start:start + size]).decode()
        if "/src/" not in path:
            raise EvidenceError("Location path has no source root: %#x" % slot)
        return path[path.rindex("/l1/") + 1:] if "/l1/" in path else path.split("/src/")[-1], line, column


def load_image(path=BINARY, expected=SHA256):
    blob = pathlib.Path(path).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
    return Image(blob)


class Insn:
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next", "imm_at", "imm_size")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None, imm=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size
        self.imm_at, self.imm_size = imm if imm else (None, None)


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

    def modrm(vector=False):
        nonlocal pos
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
        return Insn(va, size, op, fix(a), fix(b), width if w is None else w, cc, target, imm)

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
    if byte == 0xA8:
        value = immediate(1)
        return finish("test", ("r", RAX), ("i", value), 1)
    if 0xB0 <= byte <= 0xB7:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(1)
        return finish("mov", ("r", reg), ("i", value & 0xFF), 1)
    if 0xB8 <= byte <= 0xBF:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(8 if wide else 4)
        return finish("mov", ("r", reg), ("i", value & MASK[width]), width)
    if byte == 0x69:
        reg, rm = modrm()
        value = immediate(4)
        return finish("imul3", ("r", reg), rm, width, target=value)
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
        if kind in (2, 3, 4):
            return finish({2: "not", 3: "neg", 4: "mul"}[kind], rm, w=w)
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
        vector = {(0x14, False): "unpcklps", (0x15, True): "unpckhpd", (0x5C, True): "subpd", (0x74, True): "pcmpeqb",
                  (0xDB, True): "pand"}
        if (two, opsize) in vector:
            reg, rm = modrm(True)
            return finish(vector[(two, opsize)], ("x", reg), rm, 16)
        if two in (0x58, 0x5E) and repne:
            reg, rm = modrm(True)
            return finish("addsd" if two == 0x58 else "divsd", ("x", reg), rm, 8)
        if two == 0x6E and opsize:
            reg, rm = modrm()
            return finish("movd", ("x", reg), rm, 8 if wide else 4)
        if two == 0xD7 and opsize:
            reg, rm = modrm(True)
            return finish("pmovmskb", ("r", reg), rm, 4)
        if 0x40 <= two <= 0x4F:
            reg, rm = modrm()
            return finish("cmov", ("r", reg), rm, width, cc=two & 15)
        if 0x80 <= two <= 0x8F:
            rel = immediate(4)
            return finish("jcc", cc=two & 15, target=va + pos + rel)
        if 0x90 <= two <= 0x9F:
            _, rm = modrm()
            return finish("set", rm, w=1, cc=two & 15)
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
        self.statics = {}

    def reset(self):
        self.stack[:] = b"\xa5" * STACK_SIZE
        self.heap[:] = b"\xa5" * HEAP_SIZE
        self.statics = {}

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


def double_lanes(value):
    return struct.unpack("<dd", value.to_bytes(16, "little"))


def lanes_double(low, high):
    return int.from_bytes(struct.pack("<dd", low, high), "little")


class Machine:
    def __init__(self, image, patches=None):
        self.image = image
        self.patches = patches or {}
        self.memory = Memory(image)
        self.cache = {}
        self.calls = {}
        self.slots = {}
        self.regs = [0] * 16
        self.xmm = [0] * 16
        self.cf = self.zf = self.sf = self.of = False
        self.seen = set()
        self.steps = 0
        self.keep_rdx = False

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
            5: None, 6: self.sf != self.of, 7: self.zf or self.sf != self.of,
        }[code >> 1]
        if result is None:
            raise Halt("parity condition is not modelled")
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
        self.xmm = [POISON] * 16

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
        limit = STEP_LIMIT
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
            hook = self.calls.get(row.target)
            if not hook:
                raise Halt("unmodelled call to %#x at %#x" % (row.target, row.va))
            self.stub(hook)
            return self.pop()
        elif op == "jmp":
            return row.target
        elif op == "calli":
            slot = row.a[4] if row.a[0] == "m" and row.a[1] is None else None
            hook = self.slots.get(slot)
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
            count = row.b[1] & (63 if width == 8 else 31)
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
        elif op == "movsd":
            self.xmm[row.a[1]] = self.memory.read(self.address(row.b), 8)
        elif op == "movd":
            self.xmm[row.a[1]] = self.get(row.b, width)
        elif op == "unpcklps":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            words = [(left >> 0) & MASK[4], right & MASK[4], (left >> 32) & MASK[4], (right >> 32) & MASK[4]]
            self.xmm[row.a[1]] = sum(word << (32 * index) for index, word in enumerate(words))
        elif op == "unpckhpd":
            left, right = self.xmm[row.a[1]], self.vector(row.b)
            self.xmm[row.a[1]] = (left >> 64) | ((right >> 64) << 64)
        elif op == "subpd":
            left, right = double_lanes(self.xmm[row.a[1]]), double_lanes(self.vector(row.b))
            self.xmm[row.a[1]] = lanes_double(left[0] - right[0], left[1] - right[1])
        elif op in ("addsd", "divsd"):
            left = self.xmm[row.a[1]]
            right = self.xmm[row.b[1]] if row.b[0] == "x" else self.memory.read(self.address(row.b), 8)
            low = struct.unpack("<d", (left & MASK[8]).to_bytes(8, "little"))[0]
            other = struct.unpack("<d", right.to_bytes(8, "little") if row.b[0] != "x" else (right & MASK[8]).to_bytes(8, "little"))[0]
            value = low + other if op == "addsd" else low / other
            self.xmm[row.a[1]] = (left >> 64 << 64) | int.from_bytes(struct.pack("<d", value), "little")
        elif op == "pcmpeqb":
            left, right = self.xmm[row.a[1]].to_bytes(16, "little"), self.vector(row.b).to_bytes(16, "little")
            self.xmm[row.a[1]] = int.from_bytes(bytes(0xFF if x == y else 0 for x, y in zip(left, right)), "little")
        elif op == "pand":
            self.xmm[row.a[1]] &= self.vector(row.b)
        elif op == "pmovmskb":
            data = self.vector(row.b).to_bytes(16, "little")
            self.put(row.a, 4, sum(((value >> 7) & 1) << index for index, value in enumerate(data)))
        elif op == "nop":
            pass
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))
        return row.next

    def vector(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        return int.from_bytes(self.memory.bytes_at(self.address(operand), 16), "little")


def lcg(variant):
    state = variant & MASK[8]
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & MASK[8]
        yield state >> 32


def pattern(variant, size):
    draw = lcg(variant)
    data = bytearray()
    while len(data) < size:
        data += (next(draw) & MASK[4]).to_bytes(4, "little")
    return bytes(data[:size])


class Case:
    """One input. Sizes are u64; position is the signed entry for the asset, None when absent."""
    __slots__ = ("label", "asset", "books", "budget", "size", "reduce_only", "side", "diff_at", "pred_taker",
                 "pred_slot", "keys", "height", "position", "cap_maker", "cap_taker", "cap_other", "margin_maker",
                 "margin_taker", "tag", "price", "mask", "flag", "once", "variant", "no_root")

    def __init__(self, label, **fields):
        self.label = label
        self.asset, self.books, self.budget, self.size = 10001, 2, 10, 10
        self.reduce_only, self.side, self.diff_at = 0, 0, 3
        self.pred_taker, self.pred_slot = False, False
        self.keys, self.height, self.position, self.no_root = (), 0, None, False
        self.cap_maker, self.cap_taker, self.cap_other = MASK[8], MASK[8], MASK[8]
        self.margin_maker, self.margin_taker = 1500000000, 2500000000
        self.tag, self.price, self.mask, self.flag, self.once, self.variant = 1, 1000, 0x101, 1, 0, 1
        for name, value in fields.items():
            setattr(self, name, value)


def blobs(case):
    """Deterministic slot, taker and context bytes for one case."""
    slot = bytearray(pattern(case.variant * 2 + 1, 0xF8))
    taker = bytearray(pattern(case.variant * 2 + 2, 0x80))
    user = pattern(case.variant * 2 + 3, 20)
    other = bytearray(user)
    if case.diff_at is not None:
        other[case.diff_at] ^= 0x41
    slot[0xE0:0xF4] = user
    taker[0x50:0x64] = other
    slot[0xB0] = case.reduce_only
    slot[0xC8:0xD0] = case.size.to_bytes(8, "little")
    taker[0x40:0x48] = case.price.to_bytes(8, "little")
    taker[0x64] = case.side
    return bytes(slot), bytes(taker), bytes(pattern(case.variant * 2 + 4, 0x70))


class Harness:
    """Lay one case out in memory, stub the callees and run the target bytes."""

    def __init__(self, image, copy, patches=None):
        self.image = image
        self.name, self.start, self.ctx_offsets, self.leg, self.location_slot = copy
        self.machine = Machine(image, patches)
        machine = self.machine
        machine.calls = {DROP: self.on_drop, LOOKUP: self.on_lookup, self.leg: self.on_leg}
        machine.slots = {GOT_PRED: self.on_pred, GOT_MARGIN: self.on_margin, GOT_CAP: self.on_cap,
                         GOT_MASK: self.on_mask, GOT_MEMCPY: self.on_memcpy, GOT_PANIC: self.on_panic,
                         GOT_UNWRAP: self.on_unwrap, GOT_ONCE: self.on_once}
        self.trace = []
        self.case = None
        self.cap_calls = 0
        self.margin_calls = 0

    def user_at(self, pointer):
        return self.machine.memory.bytes_at(pointer, 20)

    def on_drop(self, machine):
        self.trace.append(("drop", machine.memory.read(machine.regs[RDI], 2)))

    def on_pred(self, machine):
        user = self.user_at(machine.regs[RDI])
        self.trace.append(("pred", user))
        slot_user = machine.memory.bytes_at(SLOT + 0xE0, 20)
        machine.regs[RAX] = (0x5A00 | int(self.case.pred_slot if user == slot_user else self.case.pred_taker))

    def on_lookup(self, machine):
        self.trace.append(("lookup", machine.regs[RDI], self.user_at(machine.regs[RSI])))
        machine.regs[RAX] = ENTRY

    def on_once(self, machine):
        self.trace.append(("once", machine.regs[RDI], machine.regs[RSI]))

    def on_memcpy(self, machine):
        machine.memory.copy(machine.regs[RDI], machine.regs[RSI], machine.regs[RDX])
        machine.regs[RAX] = machine.regs[RDI]

    def on_panic(self, machine):
        raise Panicked(("panic", machine.regs[RDI]))

    def on_unwrap(self, machine):
        memory = machine.memory
        raise Panicked(("unwrap", machine.regs[RDI], machine.regs[RSI], memory.read(machine.regs[RDX], 2),
                        machine.regs[RCX], machine.regs[R8]))

    def on_margin(self, machine):
        memory = machine.memory
        record = memory.bytes_at(machine.regs[RDX], 0x4F)
        self.trace.append(("margin", machine.regs[RSI], record, machine.regs[RCX] & MASK[4]))
        value = self.case.margin_taker if self.margin_calls else self.case.margin_maker
        self.margin_calls += 1
        memory.write(machine.regs[RDI] + 0x50, 8, value)

    def on_cap(self, machine):
        memory = machine.memory
        option = memory.bytes_at(machine.regs[R9], 16)
        self.trace.append(("cap", machine.regs[RDI], machine.regs[RSI], self.user_at(machine.regs[RDX]),
                           machine.regs[RCX] & 0xFF, machine.regs[R8], option[:2], option[8:],
                           memory.read(machine.regs[RSP], 8), machine.xmm[0] & MASK[8]))
        case = self.case
        machine.regs[RAX] = case.cap_taker if self.cap_calls else case.cap_maker
        machine.regs[RDX] = case.cap_other
        machine.keep_rdx = True
        self.cap_calls += 1

    def on_leg(self, machine):
        memory = machine.memory
        closure = machine.regs[RSI]
        words = [memory.read(closure + 8 * index, 8) for index in range(12)]
        self.trace.append(("leg", machine.regs[RDX] & MASK[4], memory.bytes_at(words[0], 40), words[1],
                           memory.read(words[2], 8), words[3], memory.read(words[4], 8), memory.read(words[5], 8),
                           memory.read(words[6], 8), words[7], memory.read(words[8], 8), memory.bytes_at(words[9], 16),
                           memory.bytes_at(words[10], 17), memory.bytes_at(words[11], 40)))
        index = machine.regs[RDX] & MASK[4]
        leg = bytearray(pattern(self.case.variant * 8 + index, 0x100))
        leg[:8] = (self.case.tag if index == 0 else 1).to_bytes(8, "little")
        memory.put_bytes(machine.regs[RDI], bytes(leg))

    def on_mask(self, machine):
        fill = machine.memory.bytes_at(machine.regs[RSI], FILL_BYTES)
        self.trace.append(("mask", machine.regs[RDI], fill))
        machine.regs[RAX] = 0x5A0000 | self.case.mask

    def build_tree(self, case):
        memory = self.machine.memory
        memory.write(ENTRY + 8, 8, 0 if case.no_root else NODES)
        memory.write(ENTRY + 0x10, 8, case.height)
        keys = sorted(case.keys)
        values = {key: (case.position if key == case.asset else (key * 3 + 1) & MASK[8]) for key in keys}
        if case.height == 0:
            self.write_node(NODES, keys, values, ())
            return
        # one root over two or three leaves: every third key stays in the root
        roots, leaves, current = [], [], []
        for index, key in enumerate(keys):
            if index % 3 == 2:
                roots.append(key)
                leaves.append(current)
                current = []
            else:
                current.append(key)
        leaves.append(current)
        children = [NODES + NODE_SIZE * (index + 1) for index in range(len(leaves))]
        self.write_node(NODES, roots, values, children)
        for child, part in zip(children, leaves):
            self.write_node(child, part, values, ())

    def write_node(self, node, keys, values, edges):
        memory = self.machine.memory
        memory.write(node + 0x322, 2, len(keys))
        for index in range(len(keys), 11):
            memory.write(node + 0x2C8 + 8 * index, 8, self.case.asset)
            memory.write(node + 0x10 + 0x40 * index, 8, 0x5555)
        for index, key in enumerate(keys):
            memory.write(node + 0x2C8 + 8 * index, 8, key)
            memory.write(node + 0x10 + 0x40 * index, 8, values[key])
        for index, edge in enumerate(edges):
            memory.write(node + 0x328 + 8 * index, 8, edge)

    def run(self, case):
        """Return (kind, payload, trace, exit offsets seen)."""
        machine = self.machine
        memory = machine.memory
        memory.reset()
        self.case, self.trace, self.cap_calls, self.margin_calls = case, [], 0, 0
        machine.seen = set()
        slot, taker, head = blobs(case)
        memory.put_bytes(SLOT, slot)
        memory.put_bytes(TAKER, taker)
        memory.put_bytes(CTX, head)
        books, length, table, flag = self.ctx_offsets
        memory.write(CTX + books, 8, BOOKS)
        memory.write(CTX + length, 8, case.books)
        memory.write(CTX + flag, 1, case.flag)
        memory.statics[ONCE_STATE] = case.once
        self.build_tree(case)
        args = {RDI: OUT, RSI: case.asset, RDX: SLOT, RCX: CTX, R8: TAKER, R9: case.budget}
        try:
            machine.run(self.start, args)
        except Panicked as panic:
            return "panic", panic.args[0], self.trace, machine.seen
        out = memory.bytes_at(OUT, 0x260)
        words = {"tag": int.from_bytes(out[:8], "little"), "status": int.from_bytes(out[0x238:0x240], "little"),
                 "budget": int.from_bytes(out[0x250:0x258], "little"), "reason": out[0x258]}
        if words["tag"] != NO_FILL:
            words["fill"] = out[:FILL_BYTES]
        return "return", words, self.trace, machine.seen


def spec(copy, case):
    """Predict one run from the claim, without consulting the bytes. Returns (kind, payload, trace)."""
    _, _, ctx_offsets, leg_fn, location = copy
    books_off, length_off, table_off, flag_off = ctx_offsets
    slot, taker, head = blobs(case)
    trace = []
    index = case.asset // 10000
    if index >= case.books:
        return "panic", ("unwrap", UNWRAP_TEXT, 0x2B, 0x141, UNWRAP_VTABLE, UNWRAP_LOCATION), trace, None
    book = BOOKS + index * ENTRY_STRIDE
    trace.append(("drop", 0x141))

    def stop(status, budget, reason, label):
        return "return", {"tag": NO_FILL, "status": status, "budget": budget, "reason": reason}, trace, label

    budget = case.budget
    if budget == 0:
        return stop(NONE_WORD, 0, 3, "zero_budget")
    slot_user, taker_user = slot[0xE0:0xF4], taker[0x50:0x64]
    if slot_user == taker_user:
        return stop(NONE_WORD, budget, 2, "self_cross")
    trace.append(("pred", taker_user))
    if case.pred_taker:
        trace.append(("pred", slot_user))
        if case.pred_slot:
            return stop(NONE_WORD, budget, 2, "self_cross")
    reason, usable = 3, case.size
    if case.reduce_only:
        trace.append(("lookup", book + 0xF8, slot_user))
        known = None if case.no_root or case.asset not in case.keys else case.position
        signed = None if known is None else known - (1 << 64) if known >> 63 else known
        allowed = signed is not None and (signed < 0 if case.side else signed > 0)
        if not allowed:
            if case.once:
                trace.append(("once", ONCE_STATE, 1))
            return stop(NONE_WORD, budget, 1, "reduce_only_block")
        available = abs(signed)
        usable = min(case.size, available)
        if available < case.size:
            reason = 3 if usable >= budget else 1
    if usable == 0:
        return stop(NONE_WORD, budget, reason, "empty_slot")
    amount = min(usable, budget)

    def margin_record(body, user, kind, side):
        return (body + (CTX + table_off).to_bytes(8, "little") + case.asset.to_bytes(8, "little") + user
                + bytes((kind, side, case.flag)))

    def double_bits(value):
        return int.from_bytes(struct.pack("<d", float(value) / DIVISOR), "little")

    maker_side = case.side ^ 1
    px = case.price
    trace.append(("margin", book, margin_record(slot[0x68:0x90], slot_user, 0, maker_side), 1000000000))
    trace.append(("cap", book, case.asset, slot_user, maker_side, px, bytes(2), bytes(8), 0, double_bits(case.margin_maker)))
    if case.cap_maker < amount:
        if case.cap_maker == 0:
            return stop(NONE_WORD, budget, 0, "maker_cap_zero")
        amount, reason = case.cap_maker, 0
    trace.append(("margin", book, margin_record(taker[0x10:0x38], taker_user, 1, case.side), 1000000000))
    trace.append(("cap", book, case.asset, taker_user, case.side, px, bytes((1, taker[0x76])),
                  budget.to_bytes(8, "little"), 0, double_bits(case.margin_taker)))
    status = NONE_WORD
    if case.cap_taker < amount:
        status = WORD_MARGIN if case.cap_other < amount else WORD_POSITION
        if case.cap_taker == 0:
            return stop(status, 0, reason, "taker_cap_zero")
        amount, budget = case.cap_taker, case.cap_taker
    pair = (slot_user + taker_user) if case.side else (taker_user + slot_user)
    for index_leg in (0, 1):
        trace.append(("leg", index_leg, pair, book, case.asset, SLOT, int.from_bytes(taker[0x38:0x40], "little"), px,
                      amount, CTX, int.from_bytes(taker[0x48:0x50], "little"), taker[:0x10], taker[0x65:0x76],
                      taker[0x10:0x38]))
    notional = px * amount
    if case.tag == 2 or notional > MAX_NOTIONAL:
        return "panic", ("panic", location), trace, None
    fill = bytearray(FILL_BYTES)
    legs = [bytearray(pattern(case.variant * 8 + leg, 0x100)) for leg in (0, 1)]
    legs[0][:8] = case.tag.to_bytes(8, "little")
    legs[1][:8] = (1).to_bytes(8, "little")
    fill[:0x200] = legs[0] + legs[1]
    fill[0x200:0x208] = px.to_bytes(8, "little")
    fill[0x208:0x210] = case.asset.to_bytes(8, "little")
    fill[0x210:0x218] = amount.to_bytes(8, "little")
    fill[0x218:0x220] = notional.to_bytes(8, "little")
    fill[0x220:0x228] = bytes(8)
    fill[0x228:0x230] = head[0x60:0x68]
    fill[0x230:0x234] = head[0x68:0x6C]
    fill[0x234] = case.side
    trace.append(("mask", book, bytes(fill)))
    low, high = bool(case.mask & 1), bool(case.mask & 0x100)
    if low and high:
        return ("return", {"tag": case.tag, "status": status, "budget": budget, "reason": reason, "fill": bytes(fill)},
                trace, "fill")
    maker_bit = low if case.side else high
    if not maker_bit:
        return stop(status, budget, 0, "mask_maker")
    return stop(WORD_MARGIN, 0, reason, "mask_taker")


def structured_cases():
    cases = []

    def add(label, **fields):
        cases.append(Case(label, variant=len(cases) + 1, **fields))

    for asset, books in ((0, 1), (9999, 1), (10000, 1), (19999, 2), (20000, 2), (MASK[8], 2), (0, 0), (30000, 4)):
        add("book_bound", asset=asset, books=books)
    for budget in (0, 1):
        for diff in (None, 0, 7, 15, 16, 19):
            for pred_taker, pred_slot in ((0, 0), (0, 1), (1, 0), (1, 1)):
                add("gate", budget=budget, diff_at=diff, pred_taker=bool(pred_taker), pred_slot=bool(pred_slot))
    asset = 10001
    trees = (
        ("empty", dict(no_root=True, keys=(asset,), height=0)),
        ("leaf_only", dict(keys=(asset,), height=0)),
        ("leaf_first", dict(keys=(asset, asset + 2, asset + 4), height=0)),
        ("leaf_last", dict(keys=(asset - 4, asset - 2, asset), height=0)),
        ("leaf_miss", dict(keys=(asset - 3, asset - 1, asset + 2, asset + 3), height=0)),
        ("leaf_below", dict(keys=(asset + 1, asset + 2), height=0)),
        ("leaf_above", dict(keys=(asset - 2, asset - 1), height=0)),
        ("deep_left", dict(keys=(asset, asset + 1, asset + 2, asset + 3, asset + 4, asset + 5, asset + 6), height=1)),
        ("deep_root", dict(keys=(asset - 2, asset - 1, asset, asset + 1, asset + 2, asset + 3), height=1)),
        ("deep_right", dict(keys=(asset - 6, asset - 5, asset - 4, asset - 3, asset - 2, asset - 1, asset), height=1)),
        ("deep_miss", dict(keys=(asset - 6, asset - 5, asset - 4, asset - 3, asset - 2, asset + 1, asset + 2), height=1)),
    )
    positions = (0, 1, 3, 7, 10, 11, 30, 1 << 62, MASK[8], MASK[8] - 2, MASK[8] - 6, MASK[8] - 9, MASK[8] - 10,
                 MASK[8] - 29, 1 << 63)
    for name, shape in trees:
        for side in (0, 1):
            for position in positions:
                add("reduce_only_" + name, reduce_only=1, side=side, position=position, once=len(cases) & 1, **shape)
    for side in (0, 1):
        for position in (1, 5, 9, 10, 11, 25):
            signed = (-position & MASK[8]) if side else position
            for size in (0, 1, 5, 9, 10, 11, 25):
                for budget in (1, 5, 9, 10, 11, 25):
                    add("reduce_only_reason", reduce_only=1, side=side, position=signed, size=size, budget=budget,
                        keys=(asset,))
    for size in (0, 1, 10):
        for budget in (1, 10, 11):
            add("plain_size", size=size, budget=budget)
    edges = (0, 1, 9, 10, 11, MASK[8])
    for side in (0, 1):
        for cap_maker in edges:
            for cap_taker in edges:
                for cap_other in (0, 1, 9, 10, 11, MASK[8]):
                    add("caps", side=side, cap_maker=cap_maker, cap_taker=cap_taker, cap_other=cap_other)
    for side in (0, 1):
        for mask in (0, 1, 0x100, 0x101):
            for cap_taker, cap_other in ((MASK[8], 0), (5, 3), (5, 7)):
                for cap_maker in (MASK[8], 7):
                    add("mask", side=side, mask=mask, cap_taker=cap_taker, cap_other=cap_other, cap_maker=cap_maker)
    for px, amount in ((MAX_NOTIONAL, 1), (MAX_NOTIONAL + 1, 1), (MAX_NOTIONAL // 2, 2), (MAX_NOTIONAL // 2 + 1, 2),
                       (1 << 32, 1 << 31), (1 << 32, 1 << 32), (MASK[8], 1), (MASK[8], 2), (0, MASK[8]), (1, MAX_NOTIONAL),
                       (1, MAX_NOTIONAL + 1)):
        add("notional", price=px, budget=amount, size=amount)
    for tag in (0, 1, 2, 3):
        add("leg_tag", tag=tag)
    for margin in (0, 1, (1 << 53) + 1, (1 << 63) - 1, 1 << 63, (1 << 63) + 1025, MASK[8]):
        add("margin_double", margin_maker=margin, margin_taker=MASK[8] - margin)
    for flag in (0, 1, 2):
        add("flag", flag=flag)
    return cases


def random_cases(count):
    draw = lcg(94)

    def pick(values):
        return values[next(draw) % len(values)]

    cases = []
    sizes = (0, 1, 2, 3, 5, 8, 13, 21, 34, 1 << 40, MASK[8])
    for index in range(count):
        asset = pick((0, 7, 10000, 10003, 19999))
        keys = tuple(sorted({asset + delta for delta in (-3, -1, 0, 2, 5, 8, 9, 11) if asset + delta >= 0 and next(draw) & 1}))
        height = pick((0, 1))
        position = pick((0, 1, 5, 13, MASK[8], MASK[8] - 4, MASK[8] - 12, 1 << 63))
        budget = pick(sizes)
        size = pick(sizes)
        amount = max(1, min(budget, size))
        cases.append(Case("random", asset=asset, budget=budget, size=size, reduce_only=pick((0, 1)), side=pick((0, 1)),
                          diff_at=pick((None, 0, 19, 4, 4, 4, 4, 4)), pred_taker=bool(pick((0, 1))), pred_slot=bool(pick((0, 1))),
                          keys=keys, height=height, position=position, cap_maker=pick(sizes), cap_taker=pick(sizes),
                          cap_other=pick(sizes), margin_maker=next(draw) << 31, margin_taker=next(draw) << 32,
                          tag=pick((0, 1, 1, 1, 1, 1, 1, 2)), price=pick((1, 1000, 1 << 31, MAX_NOTIONAL // amount, MAX_NOTIONAL // amount + 1)),
                          mask=pick((0, 1, 0x100, 0x101, 0x101, 0x101)), flag=pick((0, 1)), once=pick((0, 1)), variant=20000 + index))
    return cases


def all_cases():
    return structured_cases() + random_cases(1500)


def compare(harness, copy, case):
    """Run one case. Return (None or a mismatch description, exit label)."""
    predicted = spec(copy, case)
    kind, payload, trace, label = predicted
    try:
        actual_kind, actual_payload, actual_trace, _ = harness.run(case)
    except (Halt, EvidenceError) as error:
        return "%s: machine stopped: %s" % (case.label, error), label
    if actual_kind != kind:
        return "%s: kind %s, predicted %s" % (case.label, actual_kind, kind), label
    if actual_payload != payload:
        return "%s: result differs" % case.label, label
    if actual_trace != trace:
        return "%s: callee trace differs" % case.label, label
    return None, label


def run_copy(image, copy, cases, stop_first=False, patches=None):
    harness = Harness(image, copy, patches)
    failures, exits, seen, label_of = [], {}, set(), None
    for case in cases:
        failure, label = compare(harness, copy, case)
        if failure:
            failures.append(failure)
            if stop_first:
                break
        else:
            exits[label if label else "panic"] = exits.get(label if label else "panic", 0) + 1
        seen |= harness.machine.seen
    return failures, exits, seen, harness.machine.steps


# ---- the fill mask wrapper ----

class MaskCase:
    __slots__ = ("asset", "length", "first", "second", "oracle", "variant")

    def __init__(self, asset, length, first, second, oracle=77, variant=1):
        self.asset, self.length, self.first, self.second, self.oracle, self.variant = asset, length, first, second, oracle, variant


FILL_ADDR = HEAP_BASE + 0x4000
BOOK_ADDR = HEAP_BASE + 0x5000


def run_mask(image, case, patches=None):
    """Run the mask wrapper. Returns ('return', mask, calls) or ('panic', details, calls)."""
    machine = Machine(image, patches)
    memory = machine.memory
    memory.reset()
    fill = bytearray(pattern(case.variant + 3, 0x238))
    fill[0x208:0x210] = case.asset.to_bytes(8, "little")
    memory.put_bytes(FILL_ADDR, bytes(fill))
    memory.write(BOOK_ADDR + 0x68, 8, TABLE)
    memory.write(BOOK_ADDR + 0x70, 8, case.length)
    index = case.asset % 10000
    if index < case.length and TABLE + index * 0x60 + 0x28 < HEAP_BASE + HEAP_SIZE:
        memory.write(TABLE + index * 0x60 + 0x20, 8, case.oracle)
    calls = []

    def on_leg(run):
        at = run.regs[RDI]
        words = [memory.read(at + 8 * slot, 8) for slot in range(7)]
        which = run.regs[RSI] & MASK[4]
        calls.append((which, memory.bytes_at(words[0], 40), words[1], memory.read(words[2], 8), memory.read(words[3], 8),
                      memory.read(words[4], 8), memory.read(words[5], 8), memory.read(words[6], 8)))
        run.regs[RAX] = 0x5A5A00 | (case.second if which else case.first)

    def on_bounds(run):
        raise Panicked((run.regs[RDI], run.regs[RSI], run.regs[RDX]))

    machine.calls = {MASK_LEG: on_leg}
    machine.slots = {GOT_BOUNDS: on_bounds}
    try:
        value = machine.run(MASK_FN, {RDI: BOOK_ADDR, RSI: FILL_ADDR})
    except Panicked as panic:
        return "panic", panic.args[0], calls
    return "return", value & MASK[4], calls


def spec_mask(case):
    fill = bytearray(pattern(case.variant + 3, 0x238))
    fill[0x208:0x210] = case.asset.to_bytes(8, "little")
    index = case.asset % 10000
    if index >= case.length:
        return "panic", (index, case.length, MASK_LOCATION), []
    words = {key: int.from_bytes(fill[key:key + 8], "little") for key in (0x200, 0x208, 0x210)}
    pair = bytes(fill[0xD8:0xEC]) + bytes(fill[0x1D8:0x1EC])
    calls = [(which, pair, BOOK_ADDR, words[0x208], words[0x210], words[0x200], case.oracle, FILL_ADDR) for which in (0, 1)]
    return "return", (case.first & 1) | ((case.second & 1) << 8), calls


def mask_cases():
    cases = []
    for first in (0, 1, 2, 3, 0xFE, 0xFF):
        for second in (0, 1, 2, 3, 0xFE, 0xFF):
            cases.append(MaskCase(10003, 5, first, second, variant=first * 256 + second))
    for asset, length in ((9, 10), (10, 10), (19999, 3), (10000, 1), (0, 0)):
        cases.append(MaskCase(asset, length, 1, 1, variant=asset))
    return cases


def compare_mask(image, patches=None):
    failures = 0
    for case in mask_cases():
        try:
            if run_mask(image, case, patches) != spec_mask(case):
                failures += 1
        except (Halt, EvidenceError):
            failures += 1
    return failures


# ---- static facts ----

def call_slots(rows):
    """Count rip-relative indirect call slots and direct call targets of decoded rows."""
    slots, direct = {}, {}
    for row in rows:
        if row.op == "calli" and row.a[0] == "m" and row.a[1] is None:
            slots[row.a[4]] = slots.get(row.a[4], 0) + 1
        if row.op == "call":
            direct[row.target] = direct.get(row.target, 0) + 1
    return slots, direct


def normalized_hash(image, start, rows, ctx_offsets):
    """SHA-256 of the body with rel32, rip-relative disp32 and the four context disp32 fields zeroed."""
    base = image.offset(start)
    end = rows[-1].next
    body = bytearray(image.blob[base:base + end - start])
    zeroed = 0
    for row in rows:
        at = row.va - start
        if row.op in ("call", "jmp", "jcc") and row.target is not None and row.size >= 5:
            rel = struct.pack("<i", row.target - row.next)
            where = bytes(body[at:at + row.size]).rfind(rel)
            body[at + where:at + where + 4] = bytes(4)
        for operand in (row.a, row.b):
            if not operand or operand[0] != "m":
                continue
            raw = bytes(body[at:at + row.size])
            if operand[1] is None and operand[2] is None:
                where = raw.find(struct.pack("<i", operand[4] - row.next))
                if where < 0:
                    raise EvidenceError("rip displacement not found at %#x" % row.va)
                body[at + where:at + where + 4] = bytes(4)
            elif operand[4] in ctx_offsets and operand[1] not in (RSP,):
                where = raw.find(struct.pack("<i", operand[4]))
                if where < 0:
                    raise EvidenceError("context displacement not found at %#x" % row.va)
                body[at + where:at + where + 4] = bytes(4)
                zeroed += 1
    return hashlib.sha256(bytes(body)).hexdigest(), zeroed


def direct_callers(image, target):
    """Every rel32 call to target that lands at an instruction start of a decodable FDE walk."""
    text = image.text
    blob = image.blob
    sites = []
    at = blob.find(b"\xe8", text["offset"], text["offset"] + text["size"])
    limit = text["offset"] + text["size"] - 5
    while 0 <= at <= limit:
        rel = struct.unpack_from("<i", blob, at + 1)[0]
        va = at - text["offset"] + text["addr"]
        if va + 5 + rel == target:
            sites.append(va)
        at = blob.find(b"\xe8", at + 1, text["offset"] + text["size"])
    return sites


def site_facts(image, site):
    """Read the argument loads around one call site; patterns are fixed byte shapes."""
    base = image.offset(site)
    window = bytes(image.blob[base - 0x40:base])
    facts = {"stride_0xf8": b"\x48\x69\xc0\xf8\x00\x00\x00" in window}
    budget = None
    for where in range(len(window) - 8, -1, -1):
        if window[where:where + 4] == b"\x4c\x8b\x8c\x24":
            budget = struct.unpack_from("<i", window, where + 4)[0]
            break
    out = None
    for where in range(len(window) - 8, -1, -1):
        if window[where:where + 4] == b"\x48\x8d\xbc\x24":
            out = struct.unpack_from("<i", window, where + 4)[0]
            break
    facts["budget_slot"] = budget
    facts["out_slot"] = out
    return facts


def budget_feedback(image, site, facts):
    """Find the store of result +0x250 back into the budget stack slot after a call."""
    if facts["budget_slot"] is None or facts["out_slot"] is None:
        return None
    base = image.offset(site)
    window = bytes(image.blob[base:base + 0x400])
    source = struct.pack("<i", facts["out_slot"] + 0x250)
    sink = struct.pack("<i", facts["budget_slot"])
    for where in range(len(window) - 16):
        if window[where:where + 3] == b"\x48\x8b\x8c" and window[where + 3] == 0x24 and window[where + 4:where + 8] == source:
            for next_at in range(where + 8, where + 16):
                if window[next_at:next_at + 4] == b"\x48\x89\x8c\x24" and window[next_at + 4:next_at + 8] == sink:
                    return site + next_at
    return None


def status_rows(image):
    """Read the status words used here from the i32 arm table."""
    rows = []
    for word in (WORD_MARGIN, WORD_POSITION):
        index = word & 0xFF
        at = image.offset(STATUS_TABLE + 4 * index)
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, at)[0]
        if not STATUS_TABLE_ARMS[0] <= arm < STATUS_TABLE_ARMS[1]:
            raise EvidenceError("status arm outside its FDE: %#x" % arm)
        code = bytes(image.blob[image.offset(arm):image.offset(arm) + 23])
        if code[:14] != STATUS_ARM or code[18] != 0xBA:
            raise EvidenceError("unexpected status arm shape: %#x" % arm)
        text = arm + 18 + struct.unpack_from("<i", code, 14)[0]
        size = struct.unpack_from("<I", code, 19)[0]
        start = image.offset(text)
        rows.append({"word": "%#x" % word, "arm": "%#x" % arm, "text": bytes(image.blob[start:start + size]).decode()})
    return rows


def table_end(image):
    """Count leading table entries whose arm stays in the FDE."""
    count = 0
    while True:
        arm = STATUS_TABLE + struct.unpack_from("<i", image.blob, image.offset(STATUS_TABLE + 4 * count))[0]
        if not STATUS_TABLE_ARMS[0] <= arm < STATUS_TABLE_ARMS[1]:
            return count
        count += 1


def constants(image):
    blob = image.blob
    text = bytes(blob[image.offset(UNWRAP_TEXT):image.offset(UNWRAP_TEXT) + 0x2B]).decode()
    scale = struct.unpack_from("<d", blob, image.offset(DOUBLE_1E9))[0]
    zero = bytes(blob[image.offset(ZERO16):image.offset(ZERO16) + 16])
    if text != "called `Result::unwrap()` on an `Err` value":
        raise EvidenceError("unexpected unwrap text")
    if scale != DIVISOR or zero != bytes(16):
        raise EvidenceError("unexpected rodata constant")
    at = image.offset(CAP_TAIL[0])
    if bytes(blob[at:at + len(CAP_TAIL[1]) // 2]).hex() != CAP_TAIL[1]:
        raise EvidenceError("size cap tail differs")
    return {"unwrap_text": text, "divisor": scale, "zero16": zero.hex(), "cap_tail": {"va": "%#x" % CAP_TAIL[0], "bytes": CAP_TAIL[1]}}


def leg_pins(image, relative):
    rows = []
    for name, _, _, leg, _ in COPIES:
        start, end = image.exact_fde(leg)
        for offset, expected, note in LEG_PINS:
            at = image.offset(start + offset)
            if bytes(image.blob[at:at + len(expected) // 2]).hex() != expected:
                raise EvidenceError("leg builder pin failed at %#x" % (start + offset))
        body = bytes(image.blob[image.offset(start):image.offset(end)])
        writes = sum(1 for at in range(len(body) - 3) if body[at:at + 3] == b"\x48\xc7\x03")
        if writes != 1:
            raise EvidenceError("leg builder result tag writes: %d" % writes)
        rows.append({"copy": name, "leg_builder": "%#x" % start, "end": "%#x" % end,
                     "sha256": hashlib.sha256(body).hexdigest()})
    return rows


def mutation_targets(rows):
    """Yield (va, offset in instruction, xor, kind) for every conditional and every immediate."""
    for row in rows:
        if row.op == "jcc":
            yield row.va, row.size - (2 if row.size == 2 else 5), 1, "branch"
        elif row.op in ("set", "cmov"):
            yield row.va, None, 1, row.op
        if row.imm_at is not None and row.op != "jcc" and row.op != "call" and row.op != "jmp":
            yield row.va, row.imm_at, 1, "immediate"


def mutate_patch(image, row_va, at, xor):
    base = image.offset(row_va)
    window = bytes(image.blob[base:base + 16])
    if at is None:
        # set and cmov: the condition is the low nibble of the byte after 0f
        at = window.index(b"\x0f") + 1
    return {row_va + at: window[at] ^ xor}


def run_mutations(image, copy, cases, rows, reachable):
    results = []
    for va, at, xor, kind in mutation_targets(rows):
        if va not in reachable:
            results.append({"va": va, "kind": kind, "result": "unreached", "by": ""})
            continue
        patch = mutate_patch(image, va, at, xor)
        failures, _, _, _ = run_copy(image, copy, cases, stop_first=True, patches=patch)
        results.append({"va": va, "kind": kind, "result": "killed" if failures else "survived",
                        "by": failures[0].split(":")[0] if failures else ""})
    return results


def analyse(image, full=True):
    relative = image.relative_slots()
    cases = all_cases() if full else structured_cases()[:400]
    functions, exits, totals = [], {}, {"cases": len(cases), "mismatches": 0, "steps": 0}
    decoded = {}
    hashes = set()
    for copy in COPIES:
        name, start, ctx_offsets, leg, slot = copy
        begin, end = image.exact_fde(start)
        if end - begin != BODY_SIZE:
            raise EvidenceError("unexpected body size at %#x" % start)
        rows = decode_range(image, begin, end)
        decoded[name] = rows
        slots, direct = call_slots(rows)
        expected_direct = {DROP: 2, LOOKUP: 1, leg: 2}
        for target, count in expected_direct.items():
            if direct.get(target) != count:
                raise EvidenceError("direct call count differs at %#x" % target)
        normal, zeroed = normalized_hash(image, begin, rows, ctx_offsets)
        hashes.add(normal)
        location = image.location(slot, relative)
        if location[0] != "l1/src/book/book/impl_insert_order.rs" or location[1:] != (768, 85):
            raise EvidenceError("unexpected Location: %r" % (location,))
        failures, exit_counts, seen, steps = run_copy(image, copy, cases)
        if failures:
            raise EvidenceError("%s: %d mismatches, first %s" % (name, len(failures), failures[0]))
        totals["steps"] += steps
        exits[name] = exit_counts
        reachable = sum(1 for row in rows if row.va in seen)
        sites = direct_callers(image, begin)
        call_rows = []
        for site in sites:
            facts = site_facts(image, site)
            call_rows.append({"site": site, "fde": image.fde(site)[0], "stride_0xf8": facts["stride_0xf8"],
                              "budget_slot": facts["budget_slot"], "feedback": budget_feedback(image, site, facts)})
        functions.append({"copy": name, "start": begin, "end": end, "size": end - begin, "instructions": len(rows),
                          "executed": reachable, "sha256": hashlib.sha256(image.blob[image.offset(begin):image.offset(end)]).hexdigest(),
                          "normalized_sha256": normal, "context_offsets": ctx_offsets, "context_fields": zeroed,
                          "leg_builder": leg, "location_slot": slot, "location": location, "callers": call_rows,
                          "slots": slots, "seen": seen, "rows": rows})
    if len(hashes) != 1:
        raise EvidenceError("copies differ beyond addresses and context offsets")
    mask_failures = compare_mask(image)
    if mask_failures:
        raise EvidenceError("mask wrapper: %d mismatches" % mask_failures)
    target = functions[0]
    mutations = []
    if full:
        ordered = interleaved(cases)
        mutations = run_mutations(image, COPIES[0], ordered, target["rows"], target["seen"])
        mutations += mask_mutations(image)
    callees = []
    for slot, count in sorted(target["slots"].items()):
        addend = relative.get(slot)
        callees.append({"slot": slot, "name": GOT_NAMES.get(slot, "memcpy" if slot == GOT_MEMCPY else "other"), "calls": count,
                        "target": addend, "fde": image.fde(addend) if addend else None})
    return {"functions": functions, "exits": exits, "totals": totals, "mutations": mutations, "callees": callees,
            "status": status_rows(image), "table_entries": table_end(image), "constants": constants(image),
            "legs": leg_pins(image, relative), "mask_cases": len(mask_cases()),
            "mask_location": image.location(MASK_LOCATION, relative),
            "unwrap_location": image.location(UNWRAP_LOCATION, relative)}


def interleaved(cases):
    """Order cases so one of each label comes first; mutants then die early."""
    first, rest, seen = [], [], set()
    for case in cases:
        if case.label in seen:
            rest.append(case)
        else:
            seen.add(case.label)
            first.append(case)
    return first + rest


def mask_mutations(image):
    start, end = image.exact_fde(MASK_FN)
    rows = decode_range(image, start, end)
    results = []
    for va, at, xor, kind in mutation_targets(rows):
        patch = mutate_patch(image, va, at, xor)
        failed = compare_mask(image, patch)
        results.append({"va": va, "kind": kind, "result": "killed" if failed else "survived", "by": "mask" if failed else ""})
    return results


def render(evidence):
    files = {}
    rows = ["copy\tstart\tend\tsize\tinstructions\texecuted\tsha256\tnormalized_sha256\tcontext_offsets\tleg_builder\tlocation_slot\tlocation"]
    for item in evidence["functions"]:
        rows.append("\t".join((item["copy"], "%#x" % item["start"], "%#x" % item["end"], str(item["size"]), str(item["instructions"]),
                               str(item["executed"]), item["sha256"], item["normalized_sha256"],
                               ",".join("%#x" % value for value in item["context_offsets"]), "%#x" % item["leg_builder"],
                               "%#x" % item["location_slot"], "%s:%d:%d" % item["location"])))
    files["functions.tsv"] = "\n".join(rows) + "\n"
    rows = ["copy\tcall_site\tcaller_fde\tslab_stride_0xf8_before_call\tbudget_stack_slot\tresult_plus_0x250_stored_back_at"]
    for item in evidence["functions"]:
        for call in item["callers"]:
            rows.append("\t".join((item["copy"], "%#x" % call["site"], "%#x" % call["fde"], str(call["stride_0xf8"]),
                                   "" if call["budget_slot"] is None else "%#x" % call["budget_slot"],
                                   "" if call["feedback"] is None else "%#x" % call["feedback"])))
    files["callers.tsv"] = "\n".join(rows) + "\n"
    rows = ["got_slot\trole\tcalls_per_copy\ttarget\ttarget_fde_end"]
    for item in evidence["callees"]:
        rows.append("\t".join(("%#x" % item["slot"], item["name"], str(item["calls"]),
                               "%#x" % item["target"] if item["target"] else "imported",
                               "%#x" % item["fde"][1] if item["fde"] else "")))
    files["callees.tsv"] = "\n".join(rows) + "\n"
    rows = ["exit\treason_store_offset\tcondition\tcases_a\tcases_b\tcases_c"]
    for label, offset, note in EXITS:
        rows.append("\t".join((label, "%#x" % offset, note, *[str(evidence["exits"][copy[0]].get(label, 0)) for copy in COPIES])))
    rows.append("\t".join(("panic", "", "index, Location 768:85 or unwrap arm", *[str(evidence["exits"][copy[0]].get("panic", 0)) for copy in COPIES])))
    files["exits.tsv"] = "\n".join(rows) + "\n"
    rows = ["va\tkind\tresult\tfirst_detecting_family\tnote"]
    for item in evidence["mutations"]:
        note = SURVIVOR_NOTES.get(item["va"], "") if item["result"] == "survived" else UNREACHED_NOTES.get(item["va"], "")
        rows.append("\t".join(("%#x" % item["va"], item["kind"], item["result"], item["by"], note)))
    files["mutations.tsv"] = "\n".join(rows) + "\n"
    summary = {key: 0 for key in ("killed", "survived", "unreached")}
    for item in evidence["mutations"]:
        summary[item["result"]] += 1
    document = {
        "target": {"path": "artifacts/node/94/hl-node", "sha256": SHA256},
        "body_size": BODY_SIZE,
        "copies": [item["copy"] for item in evidence["functions"]],
        "normalized_sha256": evidence["functions"][0]["normalized_sha256"],
        "cases_per_copy": evidence["totals"]["cases"],
        "mismatches": evidence["totals"]["mismatches"],
        "instructions_stepped": evidence["totals"]["steps"],
        "mask_wrapper": {"fde": ["%#x" % MASK_FN, "%#x" % 0x3711CF1], "cases": evidence["mask_cases"],
                         "bounds_location": "%s:%d:%d" % evidence["mask_location"]},
        "registry_unwrap_location": "%s:%d:%d" % evidence["unwrap_location"],
        "mutations": summary,
        "status_words": evidence["status"],
        "status_table_entries": evidence["table_entries"],
        "none_word": "%#x" % NONE_WORD,
        "max_notional": "%#x" % MAX_NOTIONAL,
        "constants": evidence["constants"],
        "leg_builders": evidence["legs"],
        "leg_pins": [{"offset": "%#x" % offset, "bytes": expected, "note": note} for offset, expected, note in LEG_PINS],
    }
    files["evidence.json"] = json.dumps(document, indent=2, sort_keys=True) + "\n"
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
    evidence = analyse(load_image())
    files = render(evidence)
    write_outputs(options.out, files)
    for name in sorted(files):
        print(name, hashlib.sha256(files[name].encode()).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
