#!/usr/bin/env python3
"""Recovered semantics and decoded-bytes emulator for rocksdb

    CompactionJobStats::Reset()

mangled `_ZN7rocksdb18CompactionJobStats5ResetEv` at 0x61bd590..0x61bd60f
(127 bytes) in node #115.

The body is straight-line (no branch at all): it zeroes a fixed set of fields of
the object in `rdi`, then empties two `std::string` members by loading each one's
data pointer and writing a single NUL through it. The reconstruction is
therefore a **write set**, not a formula, and this module proves it two ways:

* `model_writes()` is the closed-form write list - (address, width, value) rows a
  reader would author from the disassembly;
* `decoded()` executes the routine's own bytes on a memory image and returns the
  *store log* the machine actually performed.

The claim is that the two agree byte for byte and row for row - including the two
writes that follow a pointer loaded out of the object, which is why the ledger
stages different buffers and a self-referential (SSO) string.

The interpreter implements exactly the instruction forms this window contains and
raises on anything else: an unmodelled path must never be silently answered.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-compaction-job-stats-reset-61bd590-115")
EXCERPT = PACKET / "main.txt"
SYMBOL = "_ZN7rocksdb18CompactionJobStats5ResetEv"
START = 0x61BD590
END = 0x61BD60F
MASK = (1 << 64) - 1

ZERO16 = (0x00, 0x10, 0x20, 0x30, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0x100)
ZERO8 = (0x40, 0xC8, 0xE8)
ZERO2 = (0x48,)
DEREF = (0xC0, 0xE0)          # the two std::string data pointers

SELF = 0x100000               # where the ledger stages the object
ARENA = 0x200000              # where it stages the two string buffers
SNAP = 0x40                   # the byte window the differential compares

INSN = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$")
# an objdump line's address + byte column, whether or not it carries instruction
# text: instructions longer than seven bytes are split, the remainder printed on
# the following line(s) with an address and bytes but no text.
LINE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)(?:\t.*)?$")


class Memory:
    """Sparse 8-byte-word space (little-endian inside a word) with a store log,
    so 'what did the routine write' is a fact rather than a summary."""

    def __init__(self, words=None):
        self.words = dict(words or {})
        self.loads = 0
        self.stores = 0
        self.log = []

    def load64(self, addr):
        self.loads += 1
        return self.words.get(int(addr) & ~7, 0)

    def load8(self, addr):
        self.loads += 1
        a = int(addr)
        return (self.words.get(a & ~7, 0) >> (8 * (a & 7))) & 0xFF

    def store64(self, addr, value, log=True):
        self.stores += 1
        a = int(addr) & ~7
        self.words[a] = int(value) & MASK
        if log:
            self.log.append((a, 8, 0))

    def store8(self, addr, value, log=True):
        self.stores += 1
        a = int(addr)
        word, shift = a & ~7, 8 * (a & 7)
        cur = self.words.get(word, 0)
        self.words[word] = ((cur & ~(0xFF << shift)) | ((int(value) & 0xFF) << shift)) & MASK
        if log:
            self.log.append((a, 1, 0))

    def store_bytes(self, addr, value, width, log=True):
        self.stores += 1
        a = int(addr)
        for i in range(width):
            word, shift = (a + i) & ~7, 8 * ((a + i) & 7)
            cur = self.words.get(word, 0)
            byte = (int(value) >> (8 * i)) & 0xFF
            self.words[word] = ((cur & ~(0xFF << shift)) | (byte << shift)) & MASK
        if log:
            self.log.append((a, width, 0))

    def snapshot(self, lo, hi):
        return {a: self.load8(a) for a in range(lo, hi)}


def _split_operands(text):
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


_ALIAS = {"eax": "%rax", "ax": "%rax", "al": "%rax", "ebx": "%rbx", "bx": "%rbx",
          "bl": "%rbx", "ecx": "%rcx", "cx": "%rcx", "cl": "%rcx", "edx": "%rdx",
          "dx": "%rdx", "dl": "%rdx", "esi": "%rsi", "si": "%rsi", "sil": "%rsi",
          "edi": "%rdi", "di": "%rdi", "dil": "%rdi", "esp": "%rsp", "sp": "%rsp",
          "spl": "%rsp", "ebp": "%rbp", "bp": "%rbp", "bpl": "%rbp"}


def _canon(name):
    n = name[1:]
    if n in _ALIAS:
        return _ALIAS[n]
    if n in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip"):
        return "%" + n
    if n.startswith("r") and n[1:].isdigit():
        return "%" + n
    if n.endswith("b") and n[:-1] in ("r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"):
        return "%" + n[:-1]
    if n.endswith("w") and n[:-1] in ("r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"):
        return "%" + n[:-1]
    raise NotImplementedError(f"register {name}")


def _reg_size(name):
    n = name[1:]
    if n in _ALIAS:
        return 4 if n.startswith("e") else (1 if n.endswith("l") else 2)
    if n in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp"):
        return 8
    if n.startswith("r") and n[1:].isdigit():
        return 8
    if n.endswith("b"):
        return 1
    if n.endswith("w"):
        return 2
    raise NotImplementedError(f"register {name}")


class Machine:
    def __init__(self, mem: Memory):
        self.m = mem
        self.r = {name: 0 for name in (
            "%rax", "%rcx", "%rdx", "%rsi", "%rdi", "%rbx", "%rbp", "%rsp",
            "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15")}
        self.x = {f"%xmm{i}": 0 for i in range(16)}
        self.steps = 0
        self.cap = 10_000

    def operand(self, text, size):
        t = text.strip()
        if t.startswith("%xmm"):
            return ("xmm", t)
        if t.startswith("$"):
            body = t[1:]
            return ("imm", int(body, 16) if body.startswith("0x") else int(body))
        if t.startswith("%"):
            return ("reg", _canon(t))
        if "(" in t:
            disp, rest = t.split("(", 1)
            base, _, tail = rest.rstrip(")").partition(",")
            addr = self.r[_canon(base)] if base else 0
            if tail:
                index, _, scale = tail.partition(",")
                addr += self.r[_canon(index)] * int(scale)
            addr = (addr + int(disp, 16)) if disp else addr
            return ("mem", addr & MASK)
        raise NotImplementedError(f"operand {text!r}")

    def read(self, op, size):
        kind, val = op
        if kind == "reg":
            return self.r[val] & ((1 << (8 * size)) - 1)
        if kind == "xmm":
            return self.x[val] & ((1 << (8 * size)) - 1)
        if kind == "mem":
            if size == 1:
                return self.m.load8(val)
            if size == 8:
                return self.m.load64(val)
            out = 0
            for i in range(size):
                out |= self.m.load8(val + i) << (8 * i)
            return out
        return val

    def write(self, op, size, value):
        kind, val = op
        mask = (1 << (8 * size)) - 1
        value &= mask
        if kind == "reg":
            self.r[val] = value if size in (4, 8) else ((self.r[val] & ~mask) | value)
            return
        if kind == "xmm":
            self.x[val] = value
            return
        if kind == "mem":
            if size == 1:
                self.m.store8(val, value)
            elif size == 8 and not (val % 8):
                self.m.store64(val, value)
            else:
                self.m.store_bytes(val, value, size)
            return
        raise NotImplementedError("writing an immediate")


_HANDLED = set()


def step(m, mn, ops, text):
    """Execute one instruction; raise on anything this window does not contain."""
    if mn in ("endbr64", "nop", "nopl", "int3"):
        return None
    if mn == "ret":
        return "ret"
    if mn == "pxor":
        if len(ops) == 2 and ops[0] == ops[1] and ops[0].startswith("%xmm"):
            m.x[ops[0]] = 0
            _HANDLED.add("pxor")
            return None
        raise NotImplementedError(f"pxor {ops}")
    if mn == "xor":
        size = _reg_size(ops[1]) if ops[1].startswith("%") else _reg_size(ops[0])
        dst = m.operand(ops[1], size)
        m.write(dst, size, 0)
        _HANDLED.add("xor")
        return None
    if mn in ("mov", "movq", "movl", "movw", "movb"):
        width = {"movq": 8, "movl": 4, "movw": 2, "movb": 1}.get(mn)
        if width is None:
            width = _reg_size(ops[-1]) if ops[-1].startswith("%") else (
                _reg_size(ops[0]) if ops[0].startswith("%") else 8)
        if ops[0].startswith("$0x"):
            width = {"movq": 8, "movl": 4, "movw": 2, "movb": 1}.get(mn, width)
        dst = m.operand(ops[-1], width)
        src = m.operand(ops[0], width)
        m.write(dst, width, m.read(src, width))
        _HANDLED.add("mov")
        return None
    if mn == "movups":
        m.write(m.operand(ops[-1], 16), 16, m.read(m.operand(ops[0], 16), 16))
        _HANDLED.add("movups")
        return None
    raise NotImplementedError(f"instruction {mn} {text!r}")


def instructions(text):
    out = []
    for line in text.splitlines():
        mm = INSN.match(line)
        if mm:
            out.append((int(mm.group(1), 16), mm.group(3).strip()))
    return out


def listing_bytes(text):
    """The listing's byte column as a {address: bytes} map, continuation lines included.

    objdump prints at most seven bytes on an instruction's own line and the rest
    on the next line(s). A check that only reads the instruction lines therefore
    sees this 127-byte window as 118 bytes: the three 11-byte `movq` stores lose
    nine bytes between them. Concatenating every line's bytes and requiring the
    addresses to be contiguous is what makes the excerpt provably the artifact.
    """
    out = {}
    for line in text.splitlines():
        m = LINE.match(line)
        if m:
            out[int(m.group(1), 16)] = bytes.fromhex(m.group(2).replace(" ", ""))
    return out


def decoded(mem, self_ptr, excerpt=None, log=False):
    """Execute the routine's own 127 bytes; the store log lands in mem.log.

    `excerpt` overrides the committed listing with other text (the fidelity
    checks doctor a store and an instruction through it).
    """
    ins = instructions(excerpt if excerpt is not None else EXCERPT.read_text())
    assert ins[0][0] == START and ins[-1][0] < END, "excerpt is not the window"
    m = Machine(mem)
    m.r["%rdi"] = self_ptr
    if log:
        mem.log, mem.loads, mem.stores = [], 0, 0
    i = 0
    while m.steps < m.cap:
        m.steps += 1
        if i >= len(ins):
            break
        a, text = ins[i]
        fields = text.split(None, 1)
        mn = fields[0]
        ops = _split_operands(fields[1]) if len(fields) > 1 and mn != "endbr64" else []
        i += 1
        if step(m, mn, ops, text) == "ret":
            return m
    raise AssertionError(f"no terminator in {m.steps} steps")


def model_writes(mem, self_ptr):
    """The write list the body encodes, **in program order** - one row per store,
    so a reader can line each row up with the instruction that performs it.

    Note what is absent: the two `std::string` *pointers* at +0xc0/+0xe0 and the
    *capacity* words at +0xd0/+0xf0. `clear()` keeps the buffer; only the size
    word and the first byte of the buffer are reset.
    """
    out = [(self_ptr + 0x40, 8, 0),      # movq $0x0,0x40(%rdi)
           (self_ptr + 0x48, 2, 0),      # mov %ax,0x48(%rdi)
           (self_ptr + 0xC8, 8, 0)]      # movq $0x0,0xc8(%rdi) - string 1 size
    out += [(self_ptr + o, 16, 0) for o in (0x00, 0x10, 0x20, 0x30)]
    out += [(self_ptr + o, 16, 0) for o in (0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0)]
    out += [(mem.load64(self_ptr + 0xC0), 1, 0),   # movb $0x0,(%rax) - string 1 data
            (self_ptr + 0xE8, 8, 0),               # movq $0x0,0xe8(%rdi) - string 2 size
            (mem.load64(self_ptr + 0xE0), 1, 0),   # movb $0x0,(%rax) - string 2 data
            (self_ptr + 0x100, 16, 0)]             # movups %xmm0,0x100(%rdi)
    return out


def apply_writes(mem, writes):
    """Apply (address, width, value) rows to a copy of `mem`."""
    out = Memory()
    out.words = dict(mem.words)
    out.loads = out.stores = 0
    for addr, width, value in writes:
        for i in range(width):
            a = addr + i
            word, shift = a & ~7, 8 * (a & 7)
            cur = out.words.get(word, 0)
            out.words[word] = ((cur & ~(0xFF << shift)) |
                               (((value >> (8 * i)) & 0xFF) << shift)) & MASK
    return out


def touched(writes):
    out = set()
    for addr, width, _ in writes:
        out.update(range(addr, addr + width))
    return out


def write_shape(rows, self_ptr=SELF):
    """Rows normalised so a re-staged string buffer does not read as a different
    write set: object offsets stay relative to the object, and the two rows that
    follow a pointer are marked external. The shape is what is invariant across
    ledger rows; the external *addresses* move with the object's own contents."""
    out = []
    for a, w, v in rows:
        out.append((a - self_ptr if self_ptr <= a < self_ptr + 0x200 else "ext", w, v))
    return out


def build_case(pattern=b"\x00", buffer_bytes=b"\x00", sso=False):
    """Stage the object at SELF and the two string buffers in ARENA.

    A self-referential (`sso`) string points inside the object, exactly as
    libstdc++ does for a short string; otherwise the pointers name real buffers.
    """
    mem = Memory()
    for i, byte in enumerate(pattern):
        mem.store8(SELF + i, byte, log=False)
    if sso:
        mem.store64(SELF + 0xC0, SELF + 0xD0, log=False)
        mem.store64(SELF + 0xE0, SELF + 0xF0, log=False)
    else:
        mem.store64(SELF + 0xC0, ARENA, log=False)
        mem.store64(SELF + 0xE0, ARENA + 0x100, log=False)
    for i in range(0x200):
        mem.store8(ARENA + i, buffer_bytes[i % len(buffer_bytes)], log=False)
    mem.log, mem.loads, mem.stores = [], 0, 0
    return mem


def agree(mem, self_ptr=SELF, excerpt=None):
    """(ok, problem, model rows, executed rows) for one staged image."""
    want = model_writes(mem, self_ptr)
    expected = apply_writes(mem, want)
    got = Memory()
    got.words = dict(mem.words)
    decoded(got, self_ptr, excerpt=excerpt, log=True)
    snap_want = expected.snapshot(0, SNAP)
    snap_got = got.snapshot(0, SNAP)
    if snap_want != snap_got:
        for a in sorted(snap_want):
            if snap_want[a] != snap_got[a]:
                return (False, f"byte 0x{a:x}: model {snap_want[a]:#x} vs bytes "
                               f"{snap_got[a]:#x}", want, got.log)
    if want != got.log:
        return False, f"write log differs: {want} vs {got.log}", want, got.log
    return True, "", want, got.log


def generate_cases(seed=7):
    """Stratified (family, object pattern, buffer byte, sso) rows."""
    import random
    rng = random.Random(seed)
    cases = [
        ("zero-object", bytes(0x130), b"\x00", False),
        ("ff-object", b"\xff" * 0x130, b"\xff", False),
        ("alternating", bytes(0x55 if i % 2 else 0xAA for i in range(0x130)), b"\x33", False),
        ("ff-object-zero-buffers", b"\xff" * 0x130, b"\x00", False),
        ("zero-object-ff-buffers", bytes(0x130), b"\xff", False),
        ("sso-string", b"\xff" * 0x130, b"\xff", True),
        ("sso-zero", bytes(0x130), b"\x00", True),
    ]
    for length in (0x40, 0x80, 0xC0, 0x130, 0x140):
        cases.append((f"len{length:#x}", bytes(length), b"\x00", False))
        cases.append((f"len{length:#x}-ff", b"\xff" * length, b"\xff", False))
    while len(cases) < 300:
        n = rng.choice([0x130, 0x140, 0x200])
        cases.append(("random", bytes(rng.randrange(256) for _ in range(n)),
                      bytes([rng.randrange(256)]), rng.random() < 0.25))
    return cases[:300]


def main():
    cases = generate_cases(seed=7)
    rows = ["family\tobject_bytes\tbuffer_byte\tsso\twrites\tbytes_touched\tagree"]
    bad = 0
    for family, pattern, buffer, sso in cases:
        mem = build_case(pattern, buffer_bytes=buffer, sso=sso)
        ok, why, want, got = agree(mem)
        if not ok:
            bad += 1
            print(f"DISAGREE {family}: {why}")
        rows.append(f"{family}\t{len(pattern)}\t{buffer[0]}\t{int(sso)}\t"
                    f"{len(want)}\t{len(touched(want))}\t{'yes' if ok else 'NO'}")
    (PACKET / "cases.tsv").write_text("\n".join(rows) + "\n")
    mem = build_case(bytes(0x130))
    m = decoded(mem, SELF, log=True)
    exec_loads, exec_stores, exec_steps = mem.loads, mem.stores, m.steps
    want = model_writes(mem, SELF)
    lines = ["# write set of the routine itself (argument staging excluded)",
             f"writes\t{len(want)}",
             f"bytes_touched\t{len(touched(want))}",
             f"loads\t{exec_loads}",
             f"stores\t{exec_stores}",
             f"steps\t{exec_steps}",
             "",
             "address\twidth\tvalue"]
    lines += [f"0x{a - SELF:x}\t{w}\t{v}" if SELF <= a < SELF + 0x200
              else f"*(0x{a:x})\t{w}\t{v}" for a, w, v in want]
    (PACKET / "writes.tsv").write_text("\n".join(lines) + "\n")
    print(f"ledger rows: {len(cases)}; disagreements: {bad}; executed writes "
          f"{len(want)} covering {len(touched(want))} bytes, in {exec_steps} steps, "
          f"{exec_loads} loads / {exec_stores} stores")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
