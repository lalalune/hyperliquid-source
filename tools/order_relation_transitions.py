#!/usr/bin/env python3
"""Pin the node #94 order relation transitions (parent, children, peer) from ELF bytes.

Every number comes from struct reads of the ELF and a small x86-64 byte decoder in
this file. No objdump or readelf output is parsed and the binary is never executed.
The decoded bytes of each target function run in a Python evaluator with stubbed
callees, and an independently written specification predicts the final state.
Standard library only.
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

LOOKUP_MUT = 0x430D380
LOOKUP_REF = 0x43075D0
SET_PEERS = 0x42FB910
DETACH = 0x42FBB50
CLEAR_PEER = 0x42FBC60
ATTACH = 0x43032B0
LINK = 0x43073D0
# Four clones of one shape: (cascade, removal callee, children, peer).
CLONES = (
    (0x42F7290, 0x42F8840, 0x43031E0, 0x43050A0),
    (0x42F7420, 0x42FA880, 0x4302F70, 0x43051F0),
    (0x42F7590, 0x42F97F0, 0x4303040, 0x4304F50),
    (0x42F7700, 0x42F7890, 0x4303110, 0x4305340),
)
TARGETS = [("set_peers", SET_PEERS), ("detach_children", DETACH), ("clear_peer", CLEAR_PEER),
           ("attach_children", ATTACH), ("link_relations", LINK)]
for _clone in CLONES:
    TARGETS.append(("cascade_cancel", _clone[0]))
    TARGETS.append(("cancel_children", _clone[2]))
    TARGETS.append(("peer_cancel", _clone[3]))

LOOKUP_PINS = (
    (0x430D51B, "0f83d2000000", "slot index must be below slab entry count"),
    (0x430D525, "4869c9f8000000", "slot stride 0xf8"),
    (0x430D52C, "833c0a02", "vacant discriminant 2"),
    (0x430D530, "0f84bd000000", "vacant slot returns null"),
    (0x430D564, "4883c220", "returned pointer is slot + 0x20"),
    (0x430D568, "31c0", "default result is null"),
    (0x430D56A, "81f9ffff0000", "all 20 user bytes must match"),
    (0x430D570, "480f44c2", "only a full user match returns the pointer"),
    (0x430D59C, "4c69c6b8000000", "tree value stride 0xb8"),
    (0x430D5F7, "4929fb", "tree arm: node plus scaled index"),
    (0x430D5FA, "4983c3a8", "tree arm: value base is node + 0x60 for index 0"),
    (0x430D5FE, "4c89d8", "tree arm returns the value pointer"),
)
# Clones whose masked bytes repeat a clone that is mutated.
MUTATION_SKIP = (CLONES[0][0], CLONES[2][0], CLONES[0][2], CLONES[2][2], CLONES[0][3], CLONES[1][3], CLONES[2][3])
CLONE_SHAPES = {"cascade_cancel": 2, "cancel_children": 2, "peer_cancel": 1}

GOT_ALLOC = 0x576DFD8
GOT_MEMCPY = 0x576DFE0
GOT_DEALLOC = 0x576E010
GOT_ALLOC_ERROR = 0x576DFB8
GOT_GROW = 0x5774458
GOT_ONCE_CALL = 0x576E8B8

PARENT_TAG, PARENT_KEY = 0x10, 0x18
PEER_TAG, PEER_KEY = 0x20, 0x28
KIDS_CAP, KIDS_PTR, KIDS_LEN = 0x30, 0x38, 0x40
BODY_SIZE = 0xB8
ONCE_STATE = 0x577AB98
REASON_CHILD, REASON_PEER = 2, 0xB

RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
VOLATILE = (RAX, RCX, RDX, RSI, RDI, R8, R9, R10, R11)
CALLEE_SAVED = (RBX, RBP, R12, R13, R14, R15)
MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}
SIGN = {1: 0x80, 2: 0x8000, 4: 0x80000000, 8: 0x8000000000000000}
STACK_TOP = 0x7FF000000
STACK_SIZE = 0x10000
HEAP_BASE = 0x600000000
HEAP_SIZE = 0x200000
RETURN_SENTINEL = 0xDEAD0000
POISON = 0xA5A5A5A5A5A5A5A5
STEP_LIMIT = 200000


class EvidenceError(Exception):
    pass


class Halt(Exception):
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
            self.sections[blob[names + row[0]:end].decode()] = {"addr": row[3], "offset": row[4], "size": row[5]}
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

    def relocation_slots(self, wanted):
        rela = self.sections[".rela.dyn"]
        dynsym, dynstr = self.sections[".dynsym"], self.sections[".dynstr"]
        found = {}
        for at in range(rela["offset"], rela["offset"] + rela["size"], 24):
            slot, info, addend = struct.unpack_from("<QQq", self.blob, at)
            if slot in wanted:
                name = ""
                if info >> 32:
                    pointer = struct.unpack_from("<I", self.blob, dynsym["offset"] + 24 * (info >> 32))[0]
                    start = dynstr["offset"] + pointer
                    name = self.blob[start:self.blob.index(b"\0", start)].decode()
                found[slot] = {"type": info & 0xFFFFFFFF, "addend": addend, "symbol": name}
        return found


def load_image(path=BINARY, expected=SHA256):
    blob = pathlib.Path(path).read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected:
        raise EvidenceError("binary SHA-256 mismatch: %s" % digest)
    return Image(blob)


class Insn:
    __slots__ = ("va", "size", "op", "a", "b", "width", "cc", "target", "next")

    def __init__(self, va, size, op, a=None, b=None, width=8, cc=None, target=None):
        self.va, self.size, self.op, self.a, self.b = va, size, op, a, b
        self.width, self.cc, self.target = width, cc, target
        self.next = va + size


GROUP1 = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
SHIFTS = {4: "shl", 5: "shr", 7: "sar"}


def decode(read, va):
    """Decode one instruction at va; read(va, n) returns n code bytes."""
    window = read(va, 16)
    pos, rex, opsize, rep = 0, 0, False, False
    while True:
        byte = window[pos]
        if byte == 0x66:
            opsize = True
        elif byte == 0xF3:
            rep = True
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

    def modrm():
        nonlocal pos
        mod_rm = window[pos]
        pos += 1
        mod, reg, rm = mod_rm >> 6, ((mod_rm >> 3) & 7) | ((rex & 4) << 1), mod_rm & 7
        if mod == 3:
            return reg, ("r", rm | ((rex & 1) << 3))
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
        nonlocal pos
        value = struct.unpack_from({1: "<b", 2: "<h", 4: "<i", 8: "<q"}[size], window, pos)[0]
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
        return Insn(va, size, op, fix(a), fix(b), width if w is None else w, cc, target)

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
    if 0xB8 <= byte <= 0xBF:
        reg = (byte & 7) | ((rex & 1) << 3)
        value = immediate(8 if wide else 4)
        return finish("mov", ("r", reg), ("i", value & MASK[width]), width)
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
    if byte == 0xCC:
        return finish("int3")
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
        if reg & 7 == 3:
            return finish("neg", rm, w=w)
        if reg & 7 == 0:
            value = immediate(1 if w == 1 else 4)
            return finish("test", rm, ("i", value), w)
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
        if two in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            reg, rm = modrm()
            if two in (0x10, 0x28, 0x6F):
                return finish("movx", ("x", reg), rm, 16)
            return finish("movx", rm, ("x", reg), 16)
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


def normalized_hash(image, start, end, rows):
    """SHA-256 of the body with call/jmp rel32 and rip-relative disp32 zeroed."""
    base = image.offset(start)
    body = bytearray(image.blob[base:base + end - start])
    for row in rows:
        at = row.va - start
        if row.op in ("call", "jmp") and row.size == 5:
            body[at + 1:at + 5] = bytes(4)
    for row in rows:
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and operand[1] is None and operand[2] is None:
                raw = bytes(body[row.va - start:row.next - start])
                disp = struct.pack("<i", operand[4] - row.next)
                where = raw.find(disp)
                if where < 0:
                    raise EvidenceError("rip displacement not found at %#x" % row.va)
                body[row.va - start + where:row.va - start + where + 4] = bytes(4)
    return hashlib.sha256(bytes(body)).hexdigest()


class Memory:
    def __init__(self, image):
        self.image = image
        self.stack = bytearray(STACK_SIZE)
        self.heap = bytearray(HEAP_SIZE)
        self.stack_base = STACK_TOP - STACK_SIZE
        self.brk = HEAP_BASE
        self.statics = {}

    def reset(self):
        self.stack[:] = b"\xa5" * STACK_SIZE
        self.brk = HEAP_BASE
        self.statics = {}

    def locate(self, addr, count):
        if self.stack_base <= addr and addr + count <= STACK_TOP:
            return self.stack, addr - self.stack_base
        if HEAP_BASE <= addr and addr + count <= self.brk:
            return self.heap, addr - HEAP_BASE
        return None, 0

    def read(self, addr, count):
        buffer, at = self.locate(addr, count)
        if buffer is not None:
            return int.from_bytes(buffer[at:at + count], "little")
        if addr in self.statics:
            return self.statics[addr] & MASK[count]
        offset = self.image.offset(addr)
        return int.from_bytes(self.image.blob[offset:offset + count], "little")

    def write(self, addr, count, value):
        buffer, at = self.locate(addr, count)
        if buffer is None:
            raise Halt("write outside stack and heap: %#x" % addr)
        buffer[at:at + count] = value.to_bytes(count, "little")

    def alloc(self, size):
        addr = self.brk
        self.brk += (size + 15) & ~15
        if self.brk > HEAP_BASE + HEAP_SIZE:
            raise Halt("heap exhausted")
        self.heap[addr - HEAP_BASE:self.brk - HEAP_BASE] = b"\xa5" * (self.brk - addr)
        return addr

    def bytes_at(self, addr, count):
        buffer, at = self.locate(addr, count)
        if buffer is None:
            raise Halt("read outside stack and heap: %#x" % addr)
        return bytes(buffer[at:at + count])

    def copy(self, dst, src, count):
        if not count:
            return
        data = self.bytes_at(src, count)
        buffer, at = self.locate(dst, count)
        if buffer is None:
            raise Halt("copy outside stack and heap: %#x" % dst)
        buffer[at:at + count] = data


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
        hook(self)
        for reg in VOLATILE:
            if reg != RAX:
                self.regs[reg] = POISON

    def run(self, entry, args, stack_args=()):
        self.memory_ready()
        self.regs = [POISON] * 16
        for reg, value in args.items():
            self.regs[reg] = value
        self.regs[RSP] = STACK_TOP - 0x100
        for value in reversed(stack_args):
            self.push(value)
        self.push(RETURN_SENTINEL)
        saved = {reg: self.regs[reg] for reg in CALLEE_SAVED}
        top = self.regs[RSP]
        pc = entry
        limit = STEP_LIMIT
        while pc != RETURN_SENTINEL:
            limit -= 1
            if limit < 0:
                raise Halt("step limit")
            row = self.cache.get(pc)
            if row is None:
                row = decode(self.read_code, pc)
                self.cache[pc] = row
            self.seen.add(pc)
            self.steps += 1
            pc = self.step(row)
        if self.regs[RSP] != top + 8:
            raise Halt("unbalanced stack")
        for reg, value in saved.items():
            if self.regs[reg] != value:
                raise Halt("callee-saved register changed")
        return self.regs[RAX]

    def memory_ready(self):
        pass

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
            if hook:
                self.stub(hook)
                return self.pop()
            return row.target
        elif op == "jmp":
            hook = self.calls.get(row.target)
            if hook:
                self.stub(hook)
                return self.pop()
            return row.target
        elif op == "calli":
            slot = row.a[4] if row.a[0] == "m" and row.a[1] is None else None
            hook = self.slots.get(slot)
            if not hook:
                raise Halt("unmodelled indirect call at %#x" % row.va)
            self.stub(hook)
        elif op == "jmpi":
            slot = row.a[4] if row.a[0] == "m" and row.a[1] is None else None
            hook = self.slots.get(slot)
            if not hook:
                raise Halt("unmodelled indirect jump at %#x" % row.va)
            self.stub(hook)
            return self.pop()
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
                self.cf = bool((value >> (count - 1)) & 1) if op != "shl" else bool((value << count) >> (8 * width) & 1)
            self.put(row.a, width, result)
        elif op == "movx":
            if row.a[0] == "x":
                self.xmm[row.a[1]] = self.xmm_read(row.b)
            elif row.b[0] == "x":
                self.memory.write(self.address(row.a), 16, self.xmm[row.b[1]])
            else:
                raise Halt("unmodelled vector move")
        elif op == "cdqe":
            low = self.regs[RAX] & MASK[4]
            self.regs[RAX] = (low - (1 << 32) if low & SIGN[4] else low) & MASK[8]
        elif op == "nop":
            pass
        else:
            raise Halt("unmodelled operation %s at %#x" % (op, row.va))
        return row.next

    def xmm_read(self, operand):
        if operand[0] == "x":
            return self.xmm[operand[1]]
        addr = self.address(operand)
        return int.from_bytes(self.memory.bytes_at(addr, 16), "little")


USER_A = bytes(range(0x10, 0x24))
USER_B = bytes(range(0x40, 0x54))
BOOK = 0x500000000
CTX = 0x510000000
EVENTS = 0x520000000
STALE = 0x7777


def clean_order(user=USER_A, parent=(0, STALE), peer=(0, STALE), kids=(), spare=0):
    return {"user": user, "parent": parent, "peer": peer, "kids": list(kids), "spare": spare}


def snapshot(orders):
    return {oid: (o["user"], tuple(o["parent"]), tuple(o["peer"]), tuple(o["kids"])) for oid, o in orders.items()}


class Harness:
    """Stub callees over evaluator memory. One instance per byte image and patch set."""

    def __init__(self, image, patches=None):
        self.machine = Machine(image, patches)
        machine = self.machine
        machine.calls[LOOKUP_MUT] = self.lookup
        machine.calls[LOOKUP_REF] = self.lookup
        for clone in CLONES:
            machine.calls[clone[1]] = self.remove
        machine.slots[GOT_ALLOC] = self.alloc
        machine.slots[GOT_MEMCPY] = self.memcpy
        machine.slots[GOT_DEALLOC] = self.dealloc
        machine.slots[GOT_ALLOC_ERROR] = self.alloc_error
        machine.slots[GOT_GROW] = self.grow
        machine.slots[GOT_ONCE_CALL] = self.once

    def begin(self, orders, fail_alloc=False, once_state=0):
        memory = self.machine.memory
        memory.reset()
        memory.statics[ONCE_STATE] = once_state
        self.fail_alloc = fail_alloc
        self.bodies = {}
        self.owner = {}
        self.log = []
        self.live = {}
        self.user_ptr = memory.alloc(32)
        for oid, order in orders.items():
            body = memory.alloc(BODY_SIZE)
            capacity = len(order["kids"]) + order["spare"]
            pointer = memory.alloc(max(capacity, 1) * 8) if capacity else 8
            memory.write(body + PARENT_TAG, 8, order["parent"][0])
            memory.write(body + PARENT_KEY, 8, order["parent"][1])
            memory.write(body + PEER_TAG, 8, order["peer"][0])
            memory.write(body + PEER_KEY, 8, order["peer"][1])
            memory.write(body + KIDS_CAP, 8, capacity)
            memory.write(body + KIDS_PTR, 8, pointer)
            memory.write(body + KIDS_LEN, 8, len(order["kids"]))
            for index, kid in enumerate(order["kids"]):
                memory.write(pointer + 8 * index, 8, kid)
            self.bodies[oid] = body
            self.owner[oid] = order["user"]
            if capacity:
                self.live[pointer] = capacity * 8

    def owned_vec(self, values, capacity=None):
        memory = self.machine.memory
        capacity = len(values) if capacity is None else capacity
        pointer = memory.alloc(capacity * 8) if capacity else 8
        for index, value in enumerate(values):
            memory.write(pointer + 8 * index, 8, value)
        if capacity:
            self.live[pointer] = capacity * 8
        return capacity, pointer

    def set_user(self, user):
        self.machine.memory.heap[self.user_ptr - HEAP_BASE:self.user_ptr - HEAP_BASE + 20] = user
        return self.user_ptr

    def state(self):
        memory = self.machine.memory
        out = {}
        for oid, body in self.bodies.items():
            count = memory.read(body + KIDS_LEN, 8)
            pointer = memory.read(body + KIDS_PTR, 8)
            kids = tuple(memory.read(pointer + 8 * i, 8) for i in range(count))
            out[oid] = (self.owner[oid], (memory.read(body + PARENT_TAG, 8), memory.read(body + PARENT_KEY, 8)),
                        (memory.read(body + PEER_TAG, 8), memory.read(body + PEER_KEY, 8)), kids)
        return out

    def lookup(self, machine):
        regs = machine.regs
        user = machine.memory.bytes_at(regs[RSI], 20)
        oid = regs[RDX]
        found = oid in self.bodies and self.owner[oid] == user
        regs[RAX] = self.bodies[oid] if found else 0

    def remove(self, machine):
        regs = machine.regs
        user = machine.memory.bytes_at(regs[RDX], 20)
        oid = regs[RSI]
        self.log.append(("remove", oid, user, regs[RCX], regs[R8], regs[R9] & 0xFF))
        body = self.bodies.pop(oid, None)
        if body is not None:
            self.live.pop(machine.memory.read(body + KIDS_PTR, 8), None)
        regs[RAX] = POISON

    def alloc(self, machine):
        regs = machine.regs
        if self.fail_alloc:
            regs[RAX] = 0
            return
        pointer = machine.memory.alloc(regs[RDI])
        self.live[pointer] = regs[RDI]
        regs[RAX] = pointer

    def memcpy(self, machine):
        regs = machine.regs
        machine.memory.copy(regs[RDI], regs[RSI], regs[RDX])
        regs[RAX] = regs[RDI]

    def dealloc(self, machine):
        regs = machine.regs
        if self.live.pop(regs[RDI], None) != regs[RSI]:
            raise Halt("bad free")
        regs[RAX] = POISON

    def alloc_error(self, machine):
        raise Halt("alloc-error")

    def grow(self, machine):
        regs = machine.regs
        memory = machine.memory
        vec = regs[RDI]
        capacity = memory.read(vec, 8)
        pointer = memory.read(vec + 8, 8)
        size = max(capacity * 2, 4)
        fresh = memory.alloc(size * 8)
        if capacity:
            memory.copy(fresh, pointer, capacity * 8)
            self.live.pop(pointer, None)
        self.live[fresh] = size * 8
        memory.write(vec, 8, size)
        memory.write(vec + 8, 8, fresh)
        regs[RAX] = POISON

    def once(self, machine):
        self.log.append(("once",))
        machine.regs[RAX] = POISON


def lookup_of(orders, user, oid):
    order = orders.get(oid)
    return order if order is not None and order["user"] == user else None


def spec_attach(orders, user, parent, children):
    target = lookup_of(orders, user, parent)
    if target is not None:
        for child in children:
            if child not in target["kids"]:
                target["kids"].append(child)
    for child in children:
        order = lookup_of(orders, user, child)
        if order is not None:
            order["parent"] = (1, parent)


def spec_detach(orders, user, oid):
    target = lookup_of(orders, user, oid)
    if target is None:
        return
    for child in list(target["kids"]):
        order = lookup_of(orders, user, child)
        if order is not None:
            order["parent"] = (0, order["parent"][1])


def spec_clear_peer(orders, user, oid):
    target = lookup_of(orders, user, oid)
    if target is None:
        return
    tag, key = target["peer"]
    target["peer"] = (0, key)
    if tag & 0xFFFFFFFF == 1:
        other = lookup_of(orders, user, key)
        if other is not None:
            other["peer"] = (0, other["peer"][1])


def spec_set_peers(orders, user, left, right):
    first = lookup_of(orders, user, left)
    if first is not None:
        first["peer"] = (1, right)
    second = lookup_of(orders, user, right)
    if second is not None:
        second["peer"] = (1, left)


def spec_link(orders, user, oid, has_parent, parent, has_peer, peer, children):
    kept = [child for child in children if lookup_of(orders, user, child) is not None]
    if has_parent & 1:
        spec_attach(orders, user, parent, [oid])
    if has_peer & 1 and lookup_of(orders, user, peer) is not None:
        spec_set_peers(orders, user, oid, peer)
    spec_attach(orders, user, oid, kept)


def spec_cascade(orders, user, oid, reason, log):
    target = lookup_of(orders, user, oid)
    if target is None:
        return True
    for child in list(target["kids"]):
        spec_cascade(orders, user, child, reason, log)
    log.append(("remove", oid, user, CTX, EVENTS, reason))
    del orders[oid]
    return False


def spec_children(orders, user, children, log):
    for child in children:
        spec_cascade(orders, user, child, REASON_CHILD, log)


def spec_peer_cancel(orders, user, oid, excluded, once_state, log):
    target = lookup_of(orders, user, oid)
    if target is None or target["peer"][0] & 0xFF == 0:
        return
    peer = target["peer"][1]
    if peer in excluded:
        if once_state:
            log.append(("once",))
        return
    spec_clear_peer(orders, user, peer)
    spec_cascade(orders, user, peer, REASON_PEER, log)


class Runner:
    """Run scenarios on real bytes and compare them with the specification."""

    def __init__(self, image, patches=None):
        self.harness = Harness(image, patches)
        self.machine = self.harness.machine
        self.runs = 0

    def finish(self, orders, expected_log, result=None, expected_result=None):
        harness = self.harness
        self.runs += 1
        if harness.live_leak():
            return "leak"
        if result is not None and (result & 0xFF) != expected_result:
            return "return value"
        if harness.log != expected_log:
            return "event log"
        got = harness.state()
        want = snapshot(orders)
        if got != want:
            return "final state"
        return None

    def guarded(self, action):
        try:
            return action()
        except (Halt, EvidenceError, KeyError, IndexError, OverflowError, struct.error, ValueError) as error:
            return "halt: %s" % error

    def attach(self, orders, user, parent, children, capacity):
        def action():
            work = json_copy(orders)
            harness = self.harness
            harness.begin(orders)
            cap, pointer = harness.owned_vec(children, capacity)
            memory = self.machine.memory
            vec = memory.alloc(24)
            memory.write(vec, 8, cap)
            memory.write(vec + 8, 8, pointer)
            memory.write(vec + 16, 8, len(children))
            self.machine.run(ATTACH, {RDI: BOOK, RSI: harness.set_user(user), RDX: parent, RCX: vec})
            spec_attach(work, user, parent, children)
            return self.finish(work, [])
        return self.guarded(action)

    def simple(self, entry, orders, user, oid, spec, right=None):
        def action():
            work = json_copy(orders)
            harness = self.harness
            harness.begin(orders)
            args = {RDI: BOOK, RSI: harness.set_user(user), RDX: oid}
            if right is not None:
                args[RCX] = right
            self.machine.run(entry, args)
            if right is None:
                spec(work, user, oid)
            else:
                spec(work, user, oid, right)
            return self.finish(work, [])
        return self.guarded(action)

    def link(self, orders, user, oid, has_parent, parent, has_peer, peer, children):
        def action():
            work = json_copy(orders)
            harness = self.harness
            harness.begin(orders)
            memory = self.machine.memory
            cap, pointer = harness.owned_vec(children)
            spec_block = memory.alloc(0x48)
            memory.write(spec_block + 0x10, 8, has_parent)
            memory.write(spec_block + 0x18, 8, parent)
            memory.write(spec_block + 0x20, 8, has_peer)
            memory.write(spec_block + 0x28, 8, peer)
            memory.write(spec_block + 0x30, 8, cap)
            memory.write(spec_block + 0x38, 8, pointer)
            memory.write(spec_block + 0x40, 8, len(children))
            self.machine.run(LINK, {RDI: BOOK, RSI: harness.set_user(user), RDX: oid, RCX: spec_block})
            spec_link(work, user, oid, has_parent, parent, has_peer, peer, children)
            return self.finish(work, [])
        return self.guarded(action)

    def cascade(self, entry, orders, user, oid, reason):
        def action():
            work = json_copy(orders)
            harness = self.harness
            harness.begin(orders)
            result = self.machine.run(entry, {RDI: BOOK, RSI: harness.set_user(user), RDX: oid, RCX: CTX, R8: EVENTS,
                                              R9: reason | 0x5500})
            log = []
            missing = spec_cascade(work, user, oid, reason, log)
            return self.finish(work, log, result, int(missing))
        return self.guarded(action)

    def children(self, entry, orders, user, children, capacity):
        def action():
            work = json_copy(orders)
            harness = self.harness
            harness.begin(orders)
            cap, pointer = harness.owned_vec(children, capacity)
            memory = self.machine.memory
            body = memory.alloc(BODY_SIZE)
            memory.write(body + KIDS_CAP, 8, cap)
            memory.write(body + KIDS_PTR, 8, pointer)
            memory.write(body + KIDS_LEN, 8, len(children))
            self.machine.run(entry, {RDI: BOOK, RSI: harness.set_user(user), RDX: POISON, RCX: body, R8: CTX, R9: EVENTS})
            log = []
            spec_children(work, user, children, log)
            return self.finish(work, log)
        return self.guarded(action)

    def excluded_tree(self, excluded, levels):
        """Build a BTreeSet<u64> shape: keys at +8, len u16 at +0x62, edges at +0x68."""
        memory = self.machine.memory

        def node(keys, edges=()):
            at = memory.alloc(0xC8)
            for index, key in enumerate(keys):
                memory.write(at + 8 + 8 * index, 8, key)
            memory.write(at + 0x62, 2, len(keys))
            for index, edge in enumerate(edges):
                memory.write(at + 0x68 + 8 * index, 8, edge)
            return at

        keys = sorted(excluded)
        if not keys:
            return 0, 0
        if levels == 0:
            return node(keys), 0
        middle = len(keys) // 2
        left, right = node(keys[:middle]), node(keys[middle + 1:])
        return node([keys[middle]], (left, right)), 1

    def peer(self, entry, orders, user, oid, excluded, levels, once_state):
        def action():
            work = json_copy(orders)
            harness = self.harness
            harness.begin(orders, once_state=once_state)
            root, height = self.excluded_tree(excluded, levels)
            self.machine.run(entry, {RDI: BOOK, RSI: harness.set_user(user), RDX: oid, RCX: root, R8: height, R9: CTX},
                             (EVENTS,))
            log = []
            spec_peer_cancel(work, user, oid, excluded, once_state, log)
            return self.finish(work, log)
        return self.guarded(action)

    def alloc_failure(self, entry, orders, user, oid):
        """A failed clone must stop before any removal is logged."""
        harness = self.harness
        harness.begin(orders, fail_alloc=True)
        self.runs += 1
        try:
            self.machine.run(entry, {RDI: BOOK, RSI: harness.set_user(user), RDX: oid, RCX: CTX, R8: EVENTS, R9: 1})
        except Halt as error:
            return None if str(error) == "alloc-error" and not harness.log else "wrong halt: %s" % error
        return "alloc failure was not reported"


def live_leak(self):
    """True if an owned buffer other than a surviving kids vector stayed allocated."""
    memory = self.machine.memory
    owned = set()
    for body in self.bodies.values():
        owned.add(memory.read(body + KIDS_PTR, 8))
    return any(pointer not in owned for pointer in self.live)


Harness.live_leak = live_leak


def json_copy(orders):
    return {oid: {"user": o["user"], "parent": tuple(o["parent"]), "peer": tuple(o["peer"]),
                  "kids": list(o["kids"]), "spare": o["spare"]} for oid, o in orders.items()}


def sequences(alphabet, longest):
    rows = [()]
    frontier = [()]
    for _ in range(longest):
        frontier = [row + (item,) for row in frontier for item in alphabet]
        rows.extend(frontier)
    return rows


def lcg(start):
    value = start
    while True:
        value = (value * 6364136223846793005 + 1442695040888963407) & MASK[8]
        yield value >> 33


def random_forest(draw):
    """Build an acyclic parent/child forest with missing, foreign and duplicate kids."""
    orders = {}
    count = 2 + next(draw) % 8
    for oid in range(1, count + 1):
        kids = []
        for _ in range(next(draw) % 4):
            roll = next(draw) % 8
            if roll == 0:
                kids.append(900 + next(draw) % 3)
            elif roll == 1:
                kids.append(800)
            elif oid < count:
                kids.append(oid + 1 + next(draw) % (count - oid))
        orders[oid] = clean_order(kids=kids, spare=next(draw) % 2)
    orders[800] = clean_order(user=USER_B)
    return orders


def attach_cases(limit=None):
    cases = []
    for parent in (1, 99):
        for existing in ((), (11,), (11, 12)):
            for spare in (0, 1):
                for children in sequences((11, 12, 13, 14, 15), 2) + [(11, 13, 14), (13, 13, 15), (12, 13, 11)]:
                    orders = {11: clean_order(), 12: clean_order(), 13: clean_order(), 15: clean_order(user=USER_B)}
                    if parent == 1:
                        orders[1] = clean_order(kids=existing, spare=spare)
                    for capacity in (len(children), len(children) + 1):
                        cases.append((orders, USER_A, parent, list(children), capacity))
    return cases[:limit] if limit else cases


def detach_cases(limit=None):
    cases = []
    for present in (True, False):
        for children in sequences((11, 14, 15), 3):
            orders = {11: clean_order(parent=(1, 1)), 15: clean_order(user=USER_B, parent=(1, 1))}
            if present:
                orders[1] = clean_order(kids=children)
            cases.append((orders, USER_A, 1))
    return cases[:limit] if limit else cases


def peer_pair_cases(limit=None):
    cases = []
    for left in (None, (0, STALE), (1, 2), (1, 3), (1, 4), (2, 2), (0x100000001, 2), (0x100, 2)):
        for right in (None, (0, STALE), (1, 1), (1, 9)):
            for foreign in (False, True):
                orders = {}
                if left is not None:
                    orders[1] = clean_order(peer=left)
                if right is not None:
                    orders[2] = clean_order(peer=right, user=USER_B if foreign else USER_A)
                orders[3] = clean_order()
                cases.append(orders)
    return cases[:limit] if limit else cases


def link_cases(limit=None):
    cases = []
    for has_parent in (0, 1, 2):
        for parent_present in (True, False):
            for has_peer in (0, 1, 2):
                for peer_state in ("live", "gone", "foreign"):
                    for present in (True, False):
                        for children in sequences((21, 24, 25), 2) + [(21, 24, 22), (24, 21, 25, 22), (25, 25, 22)]:
                            orders = {21: clean_order(), 22: clean_order(), 25: clean_order(user=USER_B)}
                            if parent_present:
                                orders[2] = clean_order(kids=(21,))
                            if present:
                                orders[1] = clean_order()
                            if peer_state == "live":
                                orders[3] = clean_order()
                            elif peer_state == "foreign":
                                orders[3] = clean_order(user=USER_B)
                            cases.append((orders, USER_A, 1, has_parent, 2, has_peer, 3, list(children)))
    return cases[:limit] if limit else cases


def forest_cases(count):
    draw = lcg(0x52454f36)
    cases = []
    for _ in range(count):
        orders = random_forest(draw)
        cases.append((orders, USER_A, 1 + next(draw) % 3, next(draw) % 256))
    cases.append(({1: clean_order(user=USER_B)}, USER_A, 1, 7))
    cases.append(({}, USER_A, 1, 7))
    return cases


def children_cases(count):
    draw = lcg(0x4348494c)
    cases = []
    for _ in range(count):
        orders = random_forest(draw)
        children = [1 + next(draw) % 12 for _ in range(next(draw) % 4)]
        cases.append((orders, USER_A, children, len(children) + next(draw) % 2))
    return cases


def peer_cases(limit=None):
    cases = []
    for start in (None, (0, 2), (1, 2), (0x100, 2), (0x101, 2), (1, 4)):
        for second in (None, (0, STALE), (1, 1), (1, 3), (1, 9), (0x100000001, 1)):
            for excluded, levels in (((), 0), ((2,), 0), ((1, 3), 0), ((1, 2, 3), 1), ((1, 3, 5), 1), ((2, 7, 9), 1)):
                for once_state in (0, 3):
                    orders = {3: clean_order(peer=(1, 2)), 5: clean_order(user=USER_B)}
                    if start is not None:
                        orders[1] = clean_order(peer=start)
                    if second is not None:
                        orders[2] = clean_order(peer=second, kids=(5, 3) if start == (0x101, 2) else ())
                    cases.append((orders, USER_A, 1, excluded, levels, once_state))
    return cases[:limit] if limit else cases


class FirstFailure(Exception):
    pass


def run_family(runner, family, entry, limit=None, stop_first=False):
    """Run one family at one entry; return (runs, [(index, reason)])."""
    failures = []

    def note(index, outcome):
        if outcome:
            failures.append((index, outcome))
            if stop_first:
                raise FirstFailure()

    try:
        return scenario_loop(runner, family, entry, limit, note, failures)
    except FirstFailure:
        return len(failures), failures


def scenario_loop(runner, family, entry, limit, note, failures):
    if family == "attach":
        for index, case in enumerate(attach_cases(limit)):
            note(index, runner.attach(*case))
        return len(attach_cases(limit)), failures
    if family == "detach":
        for index, case in enumerate(detach_cases(limit)):
            note(index, runner.simple(DETACH, case[0], case[1], case[2], spec_detach))
        return len(detach_cases(limit)), failures
    if family == "clear_peer":
        cases = peer_pair_cases(limit)
        for index, orders in enumerate(cases):
            note(index, runner.simple(CLEAR_PEER, orders, USER_A, 1, spec_clear_peer))
        return len(cases), failures
    if family == "set_peers":
        cases = peer_pair_cases(limit)
        for index, orders in enumerate(cases):
            note(index, runner.simple(SET_PEERS, orders, USER_A, 1, spec_set_peers, right=2))
        return len(cases), failures
    if family == "link":
        cases = link_cases(limit)
        for index, case in enumerate(cases):
            note(index, runner.link(*case))
        return len(cases), failures
    if family == "cascade":
        cases = forest_cases(limit or 240)
        for index, (orders, user, oid, reason) in enumerate(cases):
            note(index, runner.cascade(entry, orders, user, oid, reason))
        note(len(cases), runner.alloc_failure(entry, {1: clean_order(kids=(2,)), 2: clean_order()}, USER_A, 1))
        return len(cases) + 1, failures
    if family == "children":
        cases = children_cases(limit or 120)
        for index, case in enumerate(cases):
            note(index, runner.children(entry, *case))
        return len(cases), failures
    if family == "peer":
        cases = peer_cases(limit)
        for index, case in enumerate(cases):
            note(index, runner.peer(entry, *case))
        return len(cases), failures
    raise EvidenceError("unknown family")


FAMILIES = [("attach", ATTACH), ("detach", DETACH), ("clear_peer", CLEAR_PEER), ("set_peers", SET_PEERS), ("link", LINK)]
for _clone in CLONES:
    FAMILIES.append(("cascade", _clone[0]))
    FAMILIES.append(("children", _clone[2]))
    FAMILIES.append(("peer", _clone[3]))


def direct_callers(image, targets):
    """Every byte-level E8/E9 hit in .text landing on a target, with its FDE."""
    text = image.text
    base = text["offset"]
    blob = image.blob
    found = []
    for opcode in (0xE8, 0xE9):
        at = blob.find(bytes([opcode]), base, base + text["size"] - 4)
        while at >= 0:
            target = at + 5 + struct.unpack_from("<i", blob, at + 1)[0] - base + text["addr"]
            if target in targets:
                va = at - base + text["addr"]
                try:
                    start = image.fde(va)[0]
                except EvidenceError:
                    start = None
                found.append((target, va, opcode, start))
            at = blob.find(bytes([opcode]), at + 1, base + text["size"] - 4)
    return sorted(found)


def reason_operand(image, site):
    """Fixed-pattern scan of the 32 bytes before a site for the last r9d write."""
    offset = image.offset(site)
    window = image.blob[offset - 32:offset]
    best, value = -1, "not-fixed"
    for at in range(0, 32):
        if at + 6 <= 32 and window[at:at + 2] == b"\x41\xb9":
            best, value = at, "0x%x" % struct.unpack_from("<I", window, at + 2)[0]
        elif at + 3 <= 32 and window[at:at + 3] == b"\x45\x31\xc9":
            best, value = at, "0x0"
    return value


def mutation_points(rows):
    points = []
    for row in rows:
        if row.op == "jcc":
            points.append(row)
    return points


def mutate(row, image):
    """Flip the jcc condition bit in place; return {va: byte}."""
    offset = image.offset(row.va)
    first = image.blob[offset]
    if 0x70 <= first <= 0x7F:
        return {row.va: first ^ 1}
    if first == 0x0F:
        return {row.va + 1: image.blob[offset + 1] ^ 1}
    raise EvidenceError("not a jcc byte at %#x" % row.va)


MUTATION_FAMILY = {"set_peers": "set_peers", "detach_children": "detach", "clear_peer": "clear_peer",
                   "attach_children": "attach", "link_relations": "link", "cascade_cancel": "cascade",
                   "cancel_children": "children", "peer_cancel": "peer"}


def analyse(image):
    decoded = {}
    functions = []
    for role, va in TARGETS:
        start, end = image.exact_fde(va)
        rows = decode_range(image, start, end)
        decoded[va] = rows
        base = image.offset(start)
        functions.append({
            "role": role, "start": start, "end": end, "size": end - start,
            "sha256": hashlib.sha256(image.blob[base:base + end - start]).hexdigest(),
            "normalized_sha256": normalized_hash(image, start, end, rows),
            "instructions": len(rows),
            "branches": sum(1 for row in rows if row.op == "jcc"),
        })
    for role in ("cascade_cancel", "cancel_children", "peer_cancel"):
        if len({row["normalized_sha256"] for row in functions if row["role"] == role}) > CLONE_SHAPES[role]:
            raise EvidenceError("clone shape count changed: %s" % role)

    baseline = Runner(image)
    scenarios = []
    for family, entry in FAMILIES:
        before = baseline.machine.steps
        runs, failures = run_family(baseline, family, entry)
        scenarios.append({"family": family, "entry": entry, "runs": runs, "mismatches": len(failures),
                          "steps": baseline.machine.steps - before})
        if failures:
            raise EvidenceError("spec mismatch %s at %#x: %r" % (family, entry, failures[:3]))

    mutations = []
    for row in functions:
        if row["start"] in MUTATION_SKIP:
            continue
        family = MUTATION_FAMILY[row["role"]]
        for point in mutation_points(decoded[row["start"]]):
            reached = point.va in baseline.machine.seen
            status = "unreached"
            detail = ""
            if reached:
                runner = Runner(image, mutate(point, image))
                _, failures = run_family(runner, family, row["start"], stop_first=True)
                status = "killed" if failures else "survived"
                detail = failures[0][1].split(":")[0] if failures else ""
            mutations.append({"role": row["role"], "function": row["start"], "site": point.va,
                              "status": status, "first_failure": detail})

    coverage = []
    for row in functions:
        rows = decoded[row["start"]]
        hit = sum(1 for item in rows if item.va in baseline.machine.seen)
        row["executed"] = hit
        coverage.append(hit)

    edges = []
    for row in functions:
        for item in decoded[row["start"]]:
            if item.op == "call" or (item.op == "jmp" and not row["start"] <= item.target < row["end"]):
                edges.append({"function": row["start"], "site": item.va, "kind": item.op, "target": item.target})
            elif item.op in ("calli", "jmpi") and item.a[0] == "m" and item.a[1] is None:
                edges.append({"function": row["start"], "site": item.va, "kind": item.op + "-got", "target": item.a[4]})

    wanted = {clone[0] for clone in CLONES} | {LINK, ATTACH, DETACH, SET_PEERS, CLEAR_PEER}
    wanted |= {clone[2] for clone in CLONES} | {clone[3] for clone in CLONES}
    callers = []
    for target, site, opcode, start in direct_callers(image, wanted):
        reason = reason_operand(image, site) if target in {clone[0] for clone in CLONES} else "n/a"
        callers.append({"callee": target, "site": site, "opcode": "e8" if opcode == 0xE8 else "e9",
                        "caller_fde": start, "r9d": reason})

    # 0x430d380 and 0x43075d0 share length and bytes outside one GOT displacement.
    left = image.exact_fde(LOOKUP_MUT)
    right = image.exact_fde(LOOKUP_REF)
    a = image.blob[image.offset(left[0]):image.offset(left[1])]
    b = image.blob[image.offset(right[0]):image.offset(right[1])]
    differing = [index for index in range(min(len(a), len(b))) if a[index] != b[index]]
    if len(a) != len(b) or not differing or max(differing) - min(differing) > 3:
        raise EvidenceError("lookup bodies differ beyond one 4-byte displacement")

    slots = image.relocation_slots({GOT_ALLOC, GOT_MEMCPY, GOT_DEALLOC, GOT_ALLOC_ERROR, GOT_GROW, GOT_ONCE_CALL})
    if slots[GOT_MEMCPY]["symbol"] != "memcpy":
        raise EvidenceError("memcpy slot changed")

    example = example_cascade(image)
    return {
        "lookup_contract": check_lookup_contract(image),
        "functions": functions, "scenarios": scenarios, "mutations": mutations, "edges": edges,
        "callers": callers, "example": example,
        "lookup_pair": {"mutable": left, "shared": right, "size": len(a),
                        "differing_offsets": differing, "displacements_only": True},
        "slots": {("%#x" % slot): value for slot, value in sorted(slots.items())},
    }


def check_lookup_contract(image):
    """Exact bytes behind the stubbed lookup contract; return the pinned rows."""
    start, end = image.exact_fde(LOOKUP_MUT)
    rows = []
    for va, expected, meaning in LOOKUP_PINS:
        if not start <= va < end:
            raise EvidenceError("lookup pin outside its FDE: %#x" % va)
        offset = image.offset(va)
        found = bytes(image.blob[offset:offset + len(expected) // 2]).hex()
        if found != expected:
            raise EvidenceError("lookup pin changed at %#x" % va)
        rows.append({"va": "%#x" % va, "bytes": expected, "meaning": meaning})
    return rows


def example_cascade(image):
    """One fixed tree: 1 -> (2, 3), 2 -> (4), order removal by real bytes."""
    runner = Runner(image)
    orders = {1: clean_order(kids=(2, 3)), 2: clean_order(kids=(4,)), 3: clean_order(), 4: clean_order()}
    outcome = runner.cascade(CLONES[3][0], orders, USER_A, 1, 0x2A)
    if outcome:
        raise EvidenceError("example cascade failed: %s" % outcome)
    return [entry[1] for entry in runner.harness.log]


def render(evidence):
    outputs = {}
    lines = ["role\tfde_start\tfde_end\tsize\tinstructions\texecuted\tbranches\tsha256\tnormalized_sha256"]
    for row in evidence["functions"]:
        lines.append("%s\t%#x\t%#x\t%d\t%d\t%d\t%d\t%s\t%s" % (
            row["role"], row["start"], row["end"], row["size"], row["instructions"], row["executed"],
            row["branches"], row["sha256"], row["normalized_sha256"]))
    outputs["functions.tsv"] = "\n".join(lines) + "\n"
    lines = ["function\tsite\tkind\ttarget"]
    for row in evidence["edges"]:
        lines.append("%#x\t%#x\t%s\t%#x" % (row["function"], row["site"], row["kind"], row["target"]))
    outputs["edges.tsv"] = "\n".join(lines) + "\n"
    lines = ["callee\tsite\topcode\tcaller_fde\tr9d_pattern"]
    for row in evidence["callers"]:
        lines.append("%#x\t%#x\t%s\t%s\t%s" % (row["callee"], row["site"], row["opcode"],
                                               "%#x" % row["caller_fde"] if row["caller_fde"] else "none", row["r9d"]))
    outputs["callers.tsv"] = "\n".join(lines) + "\n"
    lines = ["family\tentry\truns\tmismatches\tsteps"]
    for row in evidence["scenarios"]:
        lines.append("%s\t%#x\t%d\t%d\t%d" % (row["family"], row["entry"], row["runs"], row["mismatches"], row["steps"]))
    outputs["scenarios.tsv"] = "\n".join(lines) + "\n"
    lines = ["role\tfunction\tjcc_site\tstatus\tfirst_failure"]
    for row in evidence["mutations"]:
        lines.append("%s\t%#x\t%#x\t%s\t%s" % (row["role"], row["function"], row["site"], row["status"],
                                               row["first_failure"]))
    outputs["mutations.tsv"] = "\n".join(lines) + "\n"
    counts = {}
    for row in evidence["mutations"]:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    summary = {
        "target_sha256": SHA256,
        "functions": len(evidence["functions"]),
        "scenario_runs": sum(row["runs"] for row in evidence["scenarios"]),
        "scenario_mismatches": sum(row["mismatches"] for row in evidence["scenarios"]),
        "mutation_counts": counts,
        "body_layout": {"parent_tag": PARENT_TAG, "parent_key": PARENT_KEY, "peer_tag": PEER_TAG, "peer_key": PEER_KEY,
                        "kids_cap": KIDS_CAP, "kids_ptr": KIDS_PTR, "kids_len": KIDS_LEN},
        "example_cascade_removal_order": evidence["example"],
        "lookup_contract": evidence["lookup_contract"],
        "lookup_pair": {
            "mutable": ["%#x" % v for v in evidence["lookup_pair"]["mutable"]],
            "shared": ["%#x" % v for v in evidence["lookup_pair"]["shared"]],
            "size": evidence["lookup_pair"]["size"],
            "differing_offsets": evidence["lookup_pair"]["differing_offsets"],
        },
        "got_slots": evidence["slots"],
    }
    outputs["evidence.json"] = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    return outputs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True, help="output directory")
    args = parser.parse_args(argv)
    image = load_image()
    outputs = render(analyse(image))
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, content in outputs.items():
        (out / name).write_text(content, encoding="utf-8")
    print("wrote %d files to %s" % (len(outputs), out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
