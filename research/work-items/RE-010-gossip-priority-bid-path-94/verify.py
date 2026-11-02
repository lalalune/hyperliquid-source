#!/usr/bin/env python3
"""Verify the node #94 gossipPriorityBid wire-to-handler path from authenticated bytes.

Static only: the target is read as data and never executed. The retained GNU and LLVM
exports are authenticated instruction by instruction against the ELF. The real arm and
wrapper instruction list then runs in the interpreter below with recording stubs for the
IPv4 parser and handler, and a separately written rule list predicts every outcome.

    python3 -I -B research/work-items/RE-010-gossip-priority-bid-path-94/verify.py [--write]

Run from any directory. Standard library only.
"""
import argparse
import bisect
import hashlib
import itertools
import json
import pathlib
import re
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[2]
TARGET = ROOT / "artifacts" / "node" / "94" / "hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
FDES = {  # start: exclusive end, each from .eh_frame_hdr and its FDE record
    0x1E60BB0: 0x1E60CF2, 0x2727BC0: 0x2727F2A, 0x4C8C0A0: 0x4C8C3E3, 0x4C8C3F0: 0x4C8C733,
    0x3B6C630: 0x3B6D090, 0x1E971D0: 0x1E97502, 0x2759240: 0x275A376, 0x4D83050: 0x4D84164,
    0x4D84170: 0x4D85284,
}
DISPATCHERS = ((0x2759240, 0x3EDE28, 0x2759865), (0x4D83050, 0x712DFC, 0x4D83675),
               (0x4D84170, 0x712F5C, 0x4D84795))
BOUND = 0x0CCCCCCCCCCCCCCC
TOP = (1 << 64) - 1
STATUS_TABLE = 0x59A8D0
STATUS_TEXT = {0xB9: "Failed to parse ip", 0x13F: "Invalid input number", 0x143: "Invalid input length"}
LITERALS = {0x3BFF70: b"slotIdipmaxGas", 0x5B59EC: b"slotIdstruct GossipPriorityBidAction with 3 elements",
            0x3F46FA: b"GossipPriorityBid", 0x3F3FEC: b"gossipPriorityBid", 0x20A074: b"type",
            0x5B44C5: b"ip", 0x5B49B8: b"maxGas"}
FIELD_TABLE = (0x5B288C, (0x3B6C702, 0x3B6C868, 0x3B6C7E5, 0x3B6CA42))
# Exact GNU text of each instruction a README claim rests on.
FACTS = {
    0x2759865: "add r12,0x8", 0x275987f: "mov rdx,rsp", 0x2759882: "mov rsi,r12",
    0x2759885: "mov rcx,r15", 0x2759888: "call 1e60bb0", 0x4d83684: "mov rcx,r15",
    0x4d83687: "call 4c8c0a0", 0x4d847a7: "call 4c8c3f0",
    0x1e60bcb: "mov rbx,QWORD PTR [rsi+0x28]", 0x1e60bd8: "mov r14,QWORD PTR [rsi]",
    0x1e60bdb: "mov rbp,QWORD PTR [rsi+0x8]", 0x1e60c29: "mov rdi,QWORD PTR [rsi+0x20]",
    0x1e60c44: "mov rax,QWORD PTR [rsi+0x18]", 0x1e60c57: "call 1573af0",
    0x1e60c69: "and rax,0xffffffffffffff00", 0x1e60c6f: "mov QWORD PTR [rsp],rbp",
    0x1e60c81: "mov r8,rbx", 0x1e60c84: "mov r9,r14", 0x1e60c87: "call 2727bc0",
    0x2727ca4: "cmp rcx,QWORD PTR [rsp+0x160]",
    0x33576a4: "mov eax,0xc5", 0x335b74b: "mov eax,0xc5", 0x3357679: "call 3b6c630",
    0x335b720: "call 3b6c630", 0x33576a0: "movups XMMWORD PTR [rbx+0x8],xmm0",
    0x3b6c6b6: "mov r14d,0x2", 0x3b6c7e5: "cmp r14,0x2", 0x3b6c7e9: "jne 3b6ce42",
    0x3b6c872: "cmp QWORD PTR [rsp],rax", 0x3b6c876: "jne 3b6ce93",
    0x3b6ca55: "cmp rcx,rdx", 0x3b6ca58: "jne 3b6cc4e",
    0x3b6cc50: "cmp r14,0x2", 0x3b6cc54: "cmovne rax,r14", 0x3b6cc58: "mov QWORD PTR [rbp+0x0],rax",
    0x3b6cc61: "mov QWORD PTR [rbp+0x8],rax", 0x3b6cc65: "mov QWORD PTR [rbp+0x10],rcx",
    0x3b6cc69: "mov QWORD PTR [rbp+0x18],r12", 0x3b6cc75: "mov QWORD PTR [rbp+0x20],rax",
    0x3b6cc79: "mov QWORD PTR [rbp+0x28],r15",
    0x1e972a9: "mov rdx,QWORD PTR [r15+0x28]", 0x1e9730a: "mov rsi,QWORD PTR [r15+0x18]",
    0x1e9730e: "mov rdx,QWORD PTR [r15+0x20]", 0x1e97369: "cmp DWORD PTR [r15],0x1",
    0x1e9736f: "mov rdx,QWORD PTR [r15+0x8]", 0x1e973cb: "mov BYTE PTR [rax+rsi*1],0xc0",
    0x1e9729a: "mov DWORD PTR [rcx+rsi*1],0x746f6c73", 0x1e97293: "mov WORD PTR [rcx+rsi*1+0x4],0x6449",
    0x1e972fc: "mov WORD PTR [rcx+rsi*1],0x7069", 0x1e9735a: "mov DWORD PTR [rcx+rsi*1],0x4778616d",
    0x1e97353: "mov WORD PTR [rcx+rsi*1+0x4],0x7361", 0x2824257: "call 1e971d0",
    0x28241f2: "add rsi,0x8", 0x1e971f9: "or r12b,0x84", 0x1e9727b: "mov BYTE PTR [rcx+rsi*1],0xa6",
    0x1e972e4: "mov BYTE PTR [rcx+rsi*1],0xa2", 0x1e9733b: "mov BYTE PTR [rcx+rsi*1],0xa6",
    0x3b6ca5e: "lea rax,[rip+0xfffffffffca47a60] # 5b44c5",
    0x3b6cac1: "lea rax,[rip+0xfffffffffca48f24] # 5b59ec", 0x3b6cacd: "mov QWORD PTR [rsp+0x28],0x6",
    0x3358a4e: "mov QWORD PTR [rbx],rax", 0x335caf5: "mov QWORD PTR [rbx],rax",
    0x2759298: "mov rax,QWORD PTR [r12]", 0x275929c: "lea rcx,[rax-0x74]",
    0x3b6c705: "jne 3b6ca03", 0x3b6c6c2: "mov r13d,0x6", 0x3b6ce42: "mov r13d,0x6",
    0x3b6ce48: "lea rax,[rip+0xfffffffffca47b69] # 5b49b8", 0x3b6ce93: "mov r13d,0x2",
    0x3b6ce99: "lea rax,[rip+0xfffffffffca47625] # 5b44c5", 0x3b6ca0f: "mov QWORD PTR [rsp+0x28],r13",
}
# The inline gates of the sibling handlers, as (offset from entry, GNU text).
SIBLING_GATES = (
    (0x11, "movabs rax,0xccccccccccccccb"), (0x1B, "mov r12,QWORD PTR [rsi+0x28]"),
    (0x26, "jae {:x}"), (0x28, "mov r14,QWORD PTR [rsi]"), (0x2B, "mov r15,QWORD PTR [rsi+0x8]"),
    (0x49, "mov WORD PTR [rdi+0x8],0x13f"), (0x4F, "mov QWORD PTR [rdi+0x10],0x1"),
    (0x59, "mov WORD PTR [rdi+0x8],0x13f"), (0x5F, "mov QWORD PTR [rdi+0x10],r12"),
    (0x79, "mov rax,QWORD PTR [rsi+0x20]"), (0x7D, "cmp rax,0x10"),
    (0x83, "mov WORD PTR [rdi+0x8],0x143"), (0xA7, "call 1573af0"),
)


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


class Elf:
    def __init__(self, blob):
        self.blob = blob
        require(blob[:6] == b"\x7fELF\x02\x01", "not a little-endian ELF64")
        shoff = struct.unpack_from("<Q", blob, 0x28)[0]
        count, names = struct.unpack_from("<HH", blob, 0x3C)
        rows = [struct.unpack_from("<IIQQQQIIQQ", blob, shoff + 64 * i) for i in range(count)]
        table = rows[names][4]
        self.sections = {}
        for row in rows:
            end = blob.index(b"\0", table + row[0])
            self.sections[blob[table + row[0]:end].decode()] = row
        self.rows = rows

    def offset(self, va):
        for row in self.rows:
            if row[1] != 8 and row[3] and row[3] <= va < row[3] + row[5]:
                return va - row[3] + row[4]
        raise Refused("unmapped %#x" % va)

    def read(self, va, size):
        at = self.offset(va)
        return self.blob[at:at + size]

    def word(self, fmt, va):
        return struct.unpack_from(fmt, self.blob, self.offset(va))[0]

    def fde_table(self):
        row = self.sections[".eh_frame_hdr"]
        require(self.blob[row[4]:row[4] + 4] == b"\x01\x1b\x03\x3b", "eh_frame_hdr encoding")
        count = struct.unpack_from("<I", self.blob, row[4] + 8)[0]
        pairs = struct.iter_unpack("<ii", self.blob[row[4] + 12:row[4] + 12 + 8 * count])
        return [(row[3] + start, row[3] + fde) for start, fde in pairs]


def parse_export(path, gnu):
    """Return {span: (start, stop, [(va, raw, mnemonic, text)])}."""
    spans = {}
    current = None
    for line in path.read_text(encoding="ascii").splitlines():
        if line.startswith("## "):
            name, start, stop = line[3:].split()
            current = spans[name] = (int(start, 16), int(stop, 16), [])
            continue
        if gnu:
            va, raw, text = line.split("\t")
        else:
            head, text = line.split("\t", 1)
            va, raw = head.split(":")
            va += ":"
        va = int(va.strip().rstrip(":"), 16)
        text = re.sub(r"\s+", " ", text.strip())
        current[2].append((va, bytes.fromhex(raw.replace(" ", "")), text.split(" ", 1)[0], text))
    return spans


def check_exports(elf, gnu, llvm):
    require(list(gnu) == list(llvm), "export span lists differ")
    instructions = 0
    for name, (start, stop, rows) in gnu.items():
        other = llvm[name]
        require(other[:2] == (start, stop), "span bounds differ: " + name)
        require([r[:2] for r in rows] == [r[:2] for r in other[2]], "decoders disagree: " + name)
        require([r[2] for r in rows] == [r[2] for r in other[2]], "mnemonics disagree: " + name)
        at = start
        for va, raw, _, _ in rows:
            require(va == at, "gap at %#x" % at)
            require(elf.read(va, len(raw)) == raw, "bytes differ at %#x" % va)
            at += len(raw)
            instructions += 1
        require(at == stop, "span does not end on a boundary: " + name)
    return instructions


def check_facts(elf, rows):
    by_va = {row[0]: row[3] for row in rows}
    for va, text in FACTS.items():
        require(by_va.get(va) == text, "fact %#x: %r" % (va, by_va.get(va)))
    for entry in (0x4C8C0A0, 0x4C8C3F0):
        for delta, text in SIBLING_GATES:
            want = text.format(entry + 0x59)
            require(by_va.get(entry + delta) == want, "sibling %#x+%#x" % (entry, delta))
    for va in (0x4C8C293, 0x4C8C5E3):
        require(by_va.get(va) == "mov WORD PTR [rbp+0x8],0xb9", "sibling ip error %#x" % va)
    for va, value in LITERALS.items():
        require(elf.read(va, len(value)) == value, "literal %#x" % va)
    for tag, text in STATUS_TEXT.items():
        arm = STATUS_TABLE + elf.word("<i", STATUS_TABLE + 4 * tag)
        code = elf.read(arm, 32)
        at = code.find(b"\x48\x8d\x35")
        require(at >= 0 and code[at + 7] == 0xBA, "status arm %#x" % tag)
        va = arm + at + 7 + struct.unpack_from("<i", code, at + 3)[0]
        size = struct.unpack_from("<I", code, at + 8)[0]
        require(elf.read(va, size).decode() == text, "status text %#x" % tag)
    table, arms = FIELD_TABLE
    for index, arm in enumerate(arms):
        require(table + elf.word("<i", table + 4 * index) == arm, "field table %d" % index)
    for base, table, arm in DISPATCHERS:
        require(table + elf.word("<i", table + 4 * 81) == arm, "dispatch table %#x" % base)


def check_extents(elf):
    table = elf.fde_table()
    starts = [row[0] for row in table]
    for start, stop in FDES.items():
        index = bisect.bisect_left(starts, start)
        require(index < len(starts) and starts[index] == start, "no FDE at %#x" % start)
        at = elf.offset(table[index][1])
        size = struct.unpack_from("<I", elf.blob, at + 12)[0]
        require(start + size == stop, "FDE end %#x" % start)
    return len(table)


def census(elf):
    """Byte-pattern superset of direct and RIP-relative references, plus stored pointers."""
    row = elf.sections[".text"]
    code = elf.blob[row[4]:row[4] + row[5]]
    targets = {0x1E60BB0: [], 0x2727BC0: []}
    for match in re.finditer(b"[\xe8\xe9]", code):
        at = match.start()
        if at + 5 <= len(code):
            target = row[3] + at + 5 + struct.unpack_from("<i", code, at + 1)[0]
            if target in targets:
                targets[target].append(row[3] + at)
    lea = re.compile(b"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", re.S)
    for match in lea.finditer(code):
        at = match.start()
        if at + 7 <= len(code):
            target = row[3] + at + 7 + struct.unpack_from("<i", code, at + 3)[0]
            if target in targets:
                targets[target].append(row[3] + at)
    rela = elf.sections[".rela.dyn"]
    stored = 0
    for _, _, addend in struct.iter_unpack("<QQq", elf.blob[rela[4]:rela[4] + rela[5]]):
        stored += addend in targets
    return {"%#x" % k: ["%#x" % v for v in values] for k, values in targets.items()}, stored


REGS64 = "rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15".split()
LOW8 = {"al": "rax", "cl": "rcx", "dil": "rdi", "r14b": "r14"}
LOW32 = {"eax": "rax", "ecx": "rcx", "edx": "rdx"}
BASE = 0x100000
SIZE = 0x10000
SIZES = {"BYTE": 1, "WORD": 2, "DWORD": 4, "QWORD": 8, "XMMWORD": 16}
POISON = 0x5A5A5A5A5A5A5A5A


class Machine:
    def __init__(self, rows, parser, handler):
        self.code = {row[0]: row[3] for row in rows}
        self.order = sorted(self.code)
        self.next = {va: self.order[i + 1] if i + 1 < len(self.order) else None
                     for i, va in enumerate(self.order)}
        self.parser, self.handler = parser, handler
        self.memory = bytearray(b"\xaa" * SIZE)
        self.regs = {name: POISON + i for i, name in enumerate(REGS64)}
        self.xmm = {}
        self.cf = self.zf = False

    def load(self, va, size):
        require(BASE <= va and va + size <= BASE + SIZE, "load %#x" % va)
        return int.from_bytes(self.memory[va - BASE:va - BASE + size], "little")

    def store(self, va, size, value):
        require(BASE <= va and va + size <= BASE + SIZE, "store %#x" % va)
        self.memory[va - BASE:va - BASE + size] = value.to_bytes(size, "little")

    def address(self, text):
        total = 0
        for part in re.findall(r"[+-]?[^+-]+", text):
            sign = -1 if part[0] == "-" else 1
            part = part.lstrip("+-")
            total += sign * (int(part, 16) if part.startswith("0x") else self.regs[part])
        return total & TOP

    def operand(self, text):
        memory = re.fullmatch(r"(BYTE|WORD|DWORD|QWORD|XMMWORD) PTR \[(.+)\]", text)
        if memory:
            return ("m", self.address(memory[2]), SIZES[memory[1]])
        if text in REGS64:
            return ("r", text, 8)
        if text in LOW8:
            return ("l", LOW8[text], 1)
        if text in LOW32:
            return ("d", LOW32[text], 4)
        if text.startswith("xmm"):
            return ("x", text, 16)
        return ("i", int(text, 16), 8)

    def get(self, place):
        kind, where, size = place
        if kind == "m":
            return self.load(where, size)
        if kind == "r":
            return self.regs[where]
        if kind in "ld":
            return self.regs[where] & ((1 << (size * 8)) - 1)
        if kind == "x":
            return self.xmm[where]
        return where

    def put(self, place, value):
        kind, where, size = place
        if kind == "m":
            self.store(where, size, value)
        elif kind == "r":
            self.regs[where] = value & TOP
        elif kind == "l":
            self.regs[where] = self.regs[where] & ~0xFF & TOP | value & 0xFF
        elif kind == "d":
            self.regs[where] = value & 0xFFFFFFFF
        elif kind == "x":
            self.xmm[where] = value
        else:
            raise Refused("store to immediate")

    def run(self, start, stop):
        pc = start
        for _ in range(500):
            if pc == stop:
                return
            require(pc in self.code, "pc %#x" % pc)
            mnemonic, _, rest = self.code[pc].partition(" ")
            operands = [item.strip() for item in rest.split(",")] if rest else []
            following = self.next[pc]
            jump = self.step(mnemonic, operands)
            pc = following if jump is None else jump
        raise Refused("step limit")

    def step(self, mnemonic, ops):
        conditions = {"jae": not self.cf, "jb": self.cf, "je": self.zf, "jne": not self.zf,
                      "jbe": self.cf or self.zf, "ja": not (self.cf or self.zf)}
        if mnemonic == "jmp":
            return int(ops[0], 16)
        if mnemonic in conditions:
            return int(ops[0], 16) if conditions[mnemonic] else None
        if mnemonic == "call":
            self.call(int(ops[0], 16))
            return None
        if mnemonic == "push":
            self.regs["rsp"] -= 8
            self.store(self.regs["rsp"], 8, self.regs[ops[0]])
        elif mnemonic == "pop":
            self.regs[ops[0]] = self.load(self.regs["rsp"], 8)
            self.regs["rsp"] += 8
        elif mnemonic == "ret":
            target = self.load(self.regs["rsp"], 8)
            self.regs["rsp"] += 8
            return target
        elif mnemonic in ("mov", "movabs", "movups", "movaps"):
            self.put(self.operand(ops[0]), self.get(self.operand(ops[1])))
        elif mnemonic == "lea":
            self.regs[ops[0]] = self.address(re.fullmatch(r"\[(.+)\]", ops[1])[1])
        elif mnemonic in ("add", "sub", "and"):
            left = self.operand(ops[0])
            a, b = self.get(left), self.get(self.operand(ops[1]))
            value = a + b if mnemonic == "add" else a - b if mnemonic == "sub" else a & b
            self.put(left, value & ((1 << (left[2] * 8)) - 1))
        elif mnemonic == "cmp":
            left = self.operand(ops[0])
            a, b = self.get(left), self.get(self.operand(ops[1]))
            self.cf, self.zf = a < b, a == b
        elif mnemonic == "test":
            self.cf = False
            self.zf = self.get(self.operand(ops[0])) & self.get(self.operand(ops[1])) == 0
        elif mnemonic in ("seta", "setae", "setb", "sete", "setne"):
            value = {"seta": not (self.cf or self.zf), "setae": not self.cf, "setb": self.cf,
                     "sete": self.zf, "setne": not self.zf}[mnemonic]
            self.put(self.operand(ops[0]), int(value))
        else:
            raise Refused("unmodelled %s" % mnemonic)
        return None

    def scramble(self):
        for i, name in enumerate(("rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11")):
            self.regs[name] = 0x7171717171717170 + i

    def call(self, target):
        regs = self.regs
        if target == 0x1E60BB0:
            regs["rsp"] -= 8
            self.store(regs["rsp"], 8, RETURN)
            self.run(target, RETURN)
            return
        arguments = dict(regs)
        stack = self.load(regs["rsp"], 8)
        if target == 0x1573AF0:
            result = self.parser(self, regs["rdi"])
        elif target == 0x2727BC0:
            self.handler(self, arguments, stack)
            result = POISON
        else:
            raise Refused("unmodelled call %#x" % target)
        self.scramble()
        regs["rax"] = result


RETURN = 0x275988D
ACTION, USER, STATE, TEXT = BASE + 0x100, BASE + 0x300, BASE + 0x400, BASE + 0x500
STACK = BASE + 0x8000
PATTERN = bytes((i * 7 + 0x31) & 0xFF for i in range(0x60))


def parse_ipv4(text):
    """The rule of the merged RE-004 parser packet; (word, consumed) or None."""
    at, octets = 0, []
    for index in range(4):
        if index:
            if at >= len(text) or text[at] != 0x2E:
                return None
            at += 1
        start = at
        value = 0
        while at < len(text) and 0x30 <= text[at] <= 0x39 and at - start < 3:
            value = value * 10 + text[at] - 0x30
            at += 1
        size = at - start
        if size == 0 or value > 255 or (size > 1 and text[start] == 0x30):
            return None
        if at < len(text) and 0x30 <= text[at] <= 0x39:
            return None
        octets.append(value)
    word = 1
    for index, value in enumerate(octets):
        word |= value << (8 * index + 8)
    return word, at


def run_case(rows, case):
    calls = []

    def parser(machine, slice_at):
        ptr = machine.load(slice_at, 8)
        size = machine.load(slice_at + 8, 8)
        text = bytes(machine.memory[ptr - BASE:ptr - BASE + size])
        got = parse_ipv4(text)
        calls.append(("parse", text.decode("latin1")))
        if got is None:
            return 0
        machine.store(slice_at, 8, ptr + got[1])
        machine.store(slice_at + 8, 8, size - got[1])
        return got[0]

    def handler(machine, regs, stack):
        calls.append(("handler", regs["rsi"], regs["rdx"], regs["rcx"], regs["r8"], regs["r9"], stack,
                      regs["rdi"]))
        machine.memory[regs["rdi"] - BASE:regs["rdi"] + 0x60 - BASE] = PATTERN
        machine.store(regs["rdi"], 2, case["handler_status"])

    machine = Machine(rows, parser, handler)
    r = machine.regs
    r["r12"], r["r13"], r["r15"] = ACTION, USER, STATE
    r["rsp"] = STACK
    saved = {name: r[name] for name in ("rbx", "rbp", "r12", "r13", "r14", "r15")}
    text = case["ip"].encode("latin1")
    machine.memory[TEXT - BASE:TEXT - BASE + len(text) + 8] = text + b"\x37" * 8
    machine.memory[USER - BASE:USER - BASE + 20] = bytes(range(1, 21))
    machine.store(ACTION, 8, 0xC5)
    machine.store(ACTION + 8, 8, int(case["max_gas"] is not None))
    machine.store(ACTION + 16, 8, TOP if case["max_gas"] is None else case["max_gas"])
    machine.store(ACTION + 24, 8, len(text) + 0x20)  # capacity, kept apart from the length
    machine.store(ACTION + 32, 8, TEXT)
    machine.store(ACTION + 40, 8, len(text))
    machine.store(ACTION + 48, 8, case["slot"])
    machine.run(0x2759865, 0x2759892 - 5)
    out = STACK + 0x68
    require(machine.regs["rsp"] == STACK, "stack not balanced")
    # r12 is advanced by the arm itself; every other callee-saved register comes back.
    saved["r12"] = ACTION + 8
    require(all(machine.regs[n] == v for n, v in saved.items()), "callee-saved register lost")
    return out, bytes(machine.memory[out - BASE:out - BASE + 0x68]), calls


def spec(case, out):
    """Independent rule list: output bytes and the ordered callee events."""
    stale = b"\xaa"
    body = bytearray(stale * 0x68)

    def refused(status, reported=None, zeroed=False):
        body[0] = 0xE
        body[8:10] = struct.pack("<H", status)
        if zeroed:
            body[10:16] = bytes(6)
        if reported is not None:
            body[16:24] = struct.pack("<Q", reported)

    calls = []
    size = len(case["ip"])
    if case["slot"] >= BOUND:
        refused(0x13F, case["slot"])
    elif case["max_gas"] is not None and case["max_gas"] >= BOUND:
        refused(0x13F, 1, True)
    elif size >= 16:
        refused(0x143)
    else:
        calls.append(("parse", case["ip"]))
        got = parse_ipv4(case["ip"].encode("latin1"))
        if got is None or got[1] != size:
            refused(0xB9)
        else:
            flag = int(case["max_gas"] is not None)
            limit = TOP if case["max_gas"] is None else case["max_gas"]
            # The output buffer is rsp+8 of the wrapper frame: return, six pushes, sub rsp,0x68.
            calls.append(("handler", STATE, STACK, got[0] & ~0xFF, case["slot"], flag, limit,
                          STACK - 8 - 0x30 - 0x68 + 8))
            if case["handler_status"] == 0x186:
                body[0] = 0xD
            else:
                body[0] = 0xE
                body[8:0x68] = PATTERN
                body[8:10] = struct.pack("<H", case["handler_status"])
    return bytes(body), calls


SLOTS = (0, 1, 4, BOUND - 1, BOUND, BOUND + 1, TOP)
GASES = (None, 0, 1, BOUND - 1, BOUND, BOUND + 1, TOP)
IPS = ("1.2.3.4", "0.0.0.0", "255.255.255.255", "123.123.123.123", "", "1.2.3", "1.2.3.4 ", "1.2.3.4.",
       "01.2.3.4", "256.1.1.1", "1.2.3.1234", "1234.1.1.1", "123.123.123.1234", "0123456789abcdef",
       "1.2.3.4" + " " * 9, "x" * 64)
STATUSES = (0x186, 0x179)


def cases():
    for slot, gas, ip, status in itertools.product(SLOTS, GASES, IPS, STATUSES):
        yield {"slot": slot, "max_gas": gas, "ip": ip, "handler_status": status}


def outcome(body, calls):
    called = "handler" if any(c[0] == "handler" for c in calls) else "parse" if calls else "none"
    tag = body[0]
    status = struct.unpack_from("<H", body, 8)[0] if tag == 0xE else 0
    reported = struct.unpack_from("<Q", body, 16)[0] if status in (0x13F,) else 0
    return tag, status, reported, called


def vector_lines(rows):
    lines = ["slot\tmax_gas\tip\thandler_status\ttag\tstatus\treported\tcalled\tip_word\tlimit_flag\tlimit"]
    for case in cases():
        out, body, calls = run_case(rows, case)
        want_body, want_calls = spec(case, out)
        require(body == want_body, "output differs: %r" % (case,))
        require(calls == want_calls, "events differ: %r" % (case,))
        tag, status, reported, called = outcome(body, calls)
        word = flag = limit = 0
        if called == "handler":
            _, _, _, word, _, flag, limit, _ = calls[-1]
        gas = "-" if case["max_gas"] is None else "%#x" % case["max_gas"]
        lines.append("%#x\t%s\t%s\t%#x\t%#x\t%#x\t%#x\t%s\t%#x\t%d\t%#x" % (
            case["slot"], gas, json.dumps(case["ip"]), case["handler_status"], tag, status, reported,
            called, word, flag, limit))
    return lines


TEXT_MUTANTS = (
    (0x1e60bd6, "jb 1e60c0c"), (0x1e60bed, "je 1e60c29"), (0x1e60c31, "jae 1e60c3b"),
    (0x1e60c67, "jne 1e60c9f"), (0x1e60c93, "je 1e60cae"), (0x1e60be2, "setae dil"),
    (0x1e60c62, "setne cl"), (0x1e60bc1, "movabs rdi,0xccccccccccccccc"),
    (0x1e60bc1, "movabs rdi,0xcccccccccccccca"), (0x1e60bcf, "lea r8,[rdi+0x2]"),
    (0x1e60bcf, "lea r8,[rdi+0x0]"), (0x1e60c2d, "cmp rdi,0xf"), (0x1e60c2d, "cmp rdi,0x11"),
    (0x1e60bcb, "mov rbx,QWORD PTR [rsi+0x20]"), (0x1e60bd8, "mov r14,QWORD PTR [rsi+0x8]"),
    (0x1e60bdb, "mov rbp,QWORD PTR [rsi+0x28]"), (0x1e60c29, "mov rdi,QWORD PTR [rsi+0x10]"),
    (0x1e60c44, "mov rax,QWORD PTR [rsi+0x10]"), (0x1e60bfc, "mov WORD PTR [rax+0x8],0x140"),
    (0x1e60c02, "mov QWORD PTR [rax+0x10],rbp"), (0x1e60c0c, "mov WORD PTR [rax+0x8],0x140"),
    (0x1e60c12, "mov QWORD PTR [rax+0x10],0x1"), (0x1e60c33, "mov WORD PTR [rax+0x8],0x13f"),
    (0x1e60ca2, "mov WORD PTR [r13+0x8],0xba"), (0x1e60c16, "mov cl,0xd"), (0x1e60c95, "mov cl,0xe"),
    (0x1e60c69, "and rax,0xffffffffffffffff"), (0x1e60c6f, "mov QWORD PTR [rsp],r14"),
    (0x1e60c78, "mov rsi,r15"), (0x1e60c7b, "mov rdx,r12"), (0x1e60c81, "mov r8,r14"),
    (0x1e60c84, "mov r9,rbx"), (0x1e60cc5, "movups xmm0,XMMWORD PTR [rsp+0x18]"),
    (0x1e60c8c, "cmp WORD PTR [rsp+0x8],0x179"), (0x2759865, "add r12,0x10"),
    (0x2759885, "mov rcx,r13"),
)


def survives(rows, va, text):
    changed = [row[:3] + (text,) if row[0] == va else row for row in rows]
    try:
        for case in cases():
            _, body, calls = run_case(changed, case)
            if (body, calls) != spec(case, None):
                return False
    except Refused:
        return False
    return True


def byte_controls(elf, gnu, wrapper_rows):
    rejected = 0
    for va, raw, _, _ in wrapper_rows:
        at = elf.offset(va)
        original = elf.blob[at]
        elf.blob[at] = original ^ 0x40
        try:
            check_exports(elf, gnu, gnu)
        except Refused:
            rejected += 1
        finally:
            elf.blob[at] = original
    return rejected


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="rewrite retained results")
    args = parser.parse_args()
    blob = bytearray(TARGET.read_bytes())
    require(hashlib.sha256(blob).hexdigest() == SHA256, "target digest")
    elf = Elf(blob)
    gnu = parse_export(HERE / "gnu.txt", True)
    llvm = parse_export(HERE / "llvm.txt", False)
    instructions = check_exports(elf, gnu, llvm)
    every = [row for _, _, rows in gnu.values() for row in rows]
    check_facts(elf, every)
    fdes = check_extents(elf)
    references, stored = census(elf)
    require(references == {"0x1e60bb0": ["0x2759888"], "0x2727bc0": ["0x1e60c87"]}, "census %r" % references)
    require(stored == 0, "stored pointer")
    machine_rows = gnu["arm_a"][2] + gnu["wrapper"][2]
    lines = vector_lines(machine_rows)
    survivors = [("%#x" % va, text) for va, text in TEXT_MUTANTS if survives(machine_rows, va, text)]
    require(not survivors, "mutants survived: %r" % survivors)
    rejected = byte_controls(elf, gnu, gnu["wrapper"][2])
    require(rejected == len(gnu["wrapper"][2]), "byte control survived")
    tally = {}
    for line in lines[1:]:
        fields = line.split("\t")
        key = "%s/%s" % (fields[5], fields[7])
        tally[key] = tally.get(key, 0) + 1
    result = {
        "target_sha256": SHA256,
        "fde_count": fdes,
        "export_spans": len(gnu),
        "export_instructions": instructions,
        "wrapper_instructions": len(gnu["wrapper"][2]),
        "facts": len(FACTS),
        "reference_census": references,
        "stored_pointers": stored,
        "cases": len(lines) - 1,
        "outcomes_status_called": dict(sorted(tally.items())),
        "text_mutants_killed": len(TEXT_MUTANTS),
        "byte_controls_rejected": rejected,
    }
    vectors = "\n".join(lines) + "\n"
    rendered = json.dumps(result, indent=1, sort_keys=True) + "\n"
    if args.write:
        (HERE / "vectors.tsv").write_text(vectors, encoding="ascii")
        (HERE / "results.json").write_text(rendered, encoding="ascii")
    require((HERE / "vectors.tsv").read_text(encoding="ascii") == vectors, "retained vectors differ")
    require((HERE / "results.json").read_text(encoding="ascii") == rendered, "retained results differ")
    print(rendered, end="")


if __name__ == "__main__":
    try:
        main()
    except Refused as error:
        sys.exit("refused: %s" % error)
