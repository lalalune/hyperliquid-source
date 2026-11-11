#!/usr/bin/env python3
"""Recovered semantics and decoded-bytes emulator for rocksdb

    CompactionPicker::AreFilesInCompaction(
        const std::vector<FileMetaData*>& files)

mangled `_ZN7rocksdb16CompactionPicker20AreFilesInCompactionERKSt6vectorIPNS_12FileMetaDataESaIS3_EE`
at 0x5d9a390..0x5d9a3cf (63 bytes) in node #115.

The routine is a leaf that touches memory only through its argument. `rsi` points
at the vector header (`{begin, end, cap}`, three 8-byte fields); the body computes
`n = (end - begin) / 8` with an arithmetic shift, then walks the elements and
returns the first non-zero byte found at offset 0xb4 of an element - i.e. it is
`AnyOf(files, &FileMetaData::being_compacted)`. The empty vector is answered from
the header alone, without touching an element.

Two artefacts are kept separate on purpose:

* `model()` is the closed-form reconstruction - what a reader would author.
* `decoded()` executes the routine's **own bytes** with a small interpreter, so a
  disagreement between the two is a real finding rather than a transcription bug.

The interpreter tracks memory as 8-byte little-endian words, models the flags each
instruction sets, and raises on any instruction or operand form it does not
implement - an unimplemented path must never be silently answered.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-are-files-in-compaction-5d9a390-115")
EXCERPT = PACKET / "main.txt"
SYMBOL = "_ZN7rocksdb16CompactionPicker20AreFilesInCompactionERKSt6vectorIPNS_12FileMetaDataESaIS3_EE"
START = 0x5D9A390
END = 0x5D9A3CF
FLAG_OFFSET = 0xB4            # FileMetaData::being_compacted (directory of the field below)
ELEMENT_SIZE = 8              # a std::vector<FileMetaData*> element is one pointer
VECTOR = 0x2F0000             # where the ledger stages the vector header
ELEMS = 0x300000              # where the ledger stages the element array
NODES = 0x400000              # where the ledger stages the pointed-to elements
MASK = (1 << 64) - 1

INSN = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$")


# --------------------------------------------------------------------------- #
# memory and machine
# --------------------------------------------------------------------------- #
class Memory:
    """A sparse 8-byte-word address space (little-endian inside a word)."""

    def __init__(self, words=None):
        self.words = dict(words or {})
        self.loads = 0
        self.stores = 0

    def load64(self, addr):
        self.loads += 1
        return self.words.get(int(addr) & ~7, 0)

    def store64(self, addr, value):
        self.stores += 1
        self.words[int(addr) & ~7] = int(value) & MASK

    def load8(self, addr):
        self.loads += 1
        addr = int(addr)
        return (self.words.get(addr & ~7, 0) >> (8 * (addr & 7))) & 0xFF

    def store8(self, addr, value):
        self.stores += 1
        addr = int(addr)
        word = addr & ~7
        shift = 8 * (addr & 7)
        cur = self.words.get(word, 0)
        self.words[word] = ((cur & ~(0xFF << shift)) | ((int(value) & 0xFF) << shift)) & MASK


def _split_operands(text):
    """Split an AT&T operand list on commas that are not inside parentheses."""
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


def _reg_size(name):
    if name.startswith("%r"):
        return 8
    if name.startswith("%e"):
        return 4
    if name.startswith("%") and name[1:] in ("al", "bl", "cl", "dl", "sil", "dil",
                                             "r8b", "r9b", "r10b", "r11b", "r12b",
                                             "r13b", "r14b", "r15b"):
        return 1
    if name.startswith("%") and name[1:] in ("ax", "bx", "cx", "dx", "si", "di",
                                             "r8w", "r9w", "r10w", "r11w", "r12w",
                                             "r13w", "r14w", "r15w"):
        return 2
    raise NotImplementedError(f"register {name}")


def _canon(name):
    """`%eax`/`%ax`/`%al` -> `%rax`; leave 64-bit names as they are."""
    n = name[1:]
    if n.startswith("r"):
        return "%" + n
    table = {"eax": "%rax", "ax": "%rax", "al": "%rax", "ebx": "%rbx", "bx": "%rbx",
             "bl": "%rbx", "ecx": "%rcx", "cx": "%rcx", "cl": "%rcx", "edx": "%rdx",
             "dx": "%rdx", "dl": "%rdx", "esi": "%rsi", "si": "%rsi", "sil": "%rsi",
             "edi": "%rdi", "di": "%rdi", "dil": "%rdi"}
    return table.get(n, "%" + n)


class Machine:
    """Executes the routine's own instructions, one objdump text line at a time."""

    def __init__(self, mem: Memory):
        self.m = mem
        self.r = {name: 0 for name in (
            "%rax", "%rcx", "%rdx", "%rsi", "%rdi", "%rbx", "%rbp", "%rsp",
            "%r8", "%r9", "%r10", "%r11", "%r12", "%r13", "%r14", "%r15")}
        self.flags = {"zf": 0, "sf": 0, "cf": 0, "of": 0}
        self.steps = 0
        self.cap = 200_000
        self.jumps = 0
        self.jump_to = None

    # -- operands ---------------------------------------------------------- #
    def operand(self, text, size):
        """Return ('reg', name) / ('mem', addr) / ('imm', value)."""
        t = text.strip()
        if t.startswith("$"):
            return ("imm", int(t[1:], 16) if t[1:].startswith(("0x", "-0x")) else int(t[1:]))
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
        if t.startswith("%") or t.startswith("0x") or t.lstrip("-").isdigit():
            return ("imm", int(t, 16) if t.startswith("0x") else int(t))
        raise NotImplementedError(f"operand {text!r}")

    def read(self, op, size):
        kind, val = op
        if kind == "reg":
            return self.r[val] & ((1 << (8 * size)) - 1)
        if kind == "mem":
            return self.m.load64(val) if size == 8 else self.m.load8(val)
        return val

    def write(self, op, size, value):
        kind, val = op
        mask = (1 << (8 * size)) - 1
        value &= mask
        if kind == "reg":
            if size == 4:                      # 32-bit writes clear the upper half
                self.r[val] = value
            elif size == 8:
                self.r[val] = value
            else:
                self.r[val] = (self.r[val] & ~mask) | value
            return
        if kind == "mem":
            if size == 8:
                self.m.store64(val, value)
            else:
                self.m.store8(val, value)
            return
        raise NotImplementedError("writing an immediate")

    def setf(self, res, a, b, size, sub=False, add=False):
        mask = (1 << (8 * size)) - 1
        res &= mask
        self.flags["zf"] = 1 if res == 0 else 0
        self.flags["sf"] = (res >> (8 * size - 1)) & 1
        if sub:
            self.flags["cf"] = 1 if a < b else 0
            self.flags["of"] = 1 if ((a ^ b) & (a ^ res)) >> (8 * size - 1) & 1 else 0
        elif add:
            self.flags["cf"] = 1 if a + b > mask else 0
            self.flags["of"] = 1 if ((a ^ res) & (b ^ res)) >> (8 * size - 1) & 1 else 0
        else:                                   # test / and / xor
            self.flags["cf"] = 0
            self.flags["of"] = 0

    def taken(self, mn):
        f = self.flags
        m = mn
        if m in ("je", "jz"):
            return f["zf"] == 1
        if m in ("jne", "jnz"):
            return f["zf"] == 0
        if m in ("jae", "jnb", "jnc"):
            return f["cf"] == 0
        if m in ("jb", "jnae", "jc"):
            return f["cf"] == 1
        if m == "ja":
            return f["cf"] == 0 and f["zf"] == 0
        if m == "jbe":
            return f["cf"] == 1 or f["zf"] == 1
        if m == "jg":
            return f["zf"] == 0 and f["sf"] == f["of"]
        if m == "jle":
            return f["zf"] == 1 or f["sf"] != f["of"]
        if m == "jl":
            return f["sf"] != f["of"]
        if m == "jge":
            return f["sf"] == f["of"]
        if m == "jmp":
            return True
        raise NotImplementedError(f"branch {mn}")


_HANDLED = set()


def step(m_exec, mn, ops, text):
    """Execute one instruction.  Every unhandled form raises, never guesses."""
    m = m_exec
    if mn in ("endbr64", "nop", "nopl", "int3"):
        return None
    if mn == "ret":
        return "ret"
    if mn in ("mov", "movabs", "movq", "movl", "movb"):
        # AT&T order: the destination is the LAST operand.
        size = _reg_size(ops[-1]) if ops[-1].startswith("%") else (
            _reg_size(ops[0]) if ops[0].startswith("%") else 8)
        dst = m.operand(ops[-1], size)
        src = m.operand(ops[0], size)
        m.write(dst, size, m.read(src, size))
        _HANDLED.add("mov")
        return None
    if mn == "movzbl":
        dst = m.operand(ops[-1], 4)
        src = m.operand(ops[0], 1)
        m.write(dst, 4, m.read(src, 1) & 0xFF)
        _HANDLED.add("movzbl")
        return None
    if mn in ("sub", "add", "and", "or", "xor", "cmp", "test"):
        size = _reg_size(ops[1]) if ops[1].startswith("%") else (
            _reg_size(ops[0]) if ops[0].startswith("%") else 8)
        a_op = m.operand(ops[1], size)
        b_op = m.operand(ops[0], size)
        a = m.read(a_op, size)
        b = m.read(b_op, size)
        if mn == "cmp":
            m.setf(a - b, a, b, size, sub=True)
        elif mn == "test":
            m.setf(a & b, a, b, size)
        else:
            res = {"sub": a - b, "add": a + b, "and": a & b, "or": a | b,
                   "xor": a ^ b}[mn]
            m.write(a_op, size, res)
            m.setf(res, a, b, size, sub=(mn == "sub"), add=(mn == "add"))
        _HANDLED.add(mn)
        return None
    if mn in ("sar", "shr", "shl", "sal"):
        size = _reg_size(ops[1].split("%")[1]) if False else (
            _reg_size([p for p in ops if p.startswith("%")][0]))
        dst = [p for p in ops if p.startswith("%")][0]
        cnt = int(ops[0][1:], 16) if ops[0].startswith("$0x") else int(ops[0][1:]) if ops[0].startswith("$") else m.r[_canon(ops[0])]
        d = m.operand(dst, size)
        v = m.read(d, size)
        if mn == "sar":
            sign = 1 << (8 * size - 1)
            v = (v - (1 << (8 * size)) if v & sign else v) >> cnt
        elif mn == "shr":
            v = (v & ((1 << (8 * size)) - 1)) >> cnt
        else:
            v = (v << cnt) & ((1 << (8 * size)) - 1)
        m.write(d, size, v)
        _HANDLED.add(mn)
        return None
    if mn == "xchg":
        if ops == ["%ax", "%ax"]:
            return None
        raise NotImplementedError(f"xchg {ops}")
    if mn.startswith("j"):
        if not m.taken(mn):
            return None
        tgt = int(ops[0].split("(")[0], 16) if "(" in ops[0] else (
            int(ops[0], 16) if not ops[0].startswith("%") else m.r[_canon(ops[0])])
        m.jump_to = tgt
        m.jumps += 1
        _HANDLED.add(mn)
        return None
    raise NotImplementedError(f"instruction {mn} {text!r}")


def instructions(text, path=None):
    """Decode the committed excerpt; `path` lets a test doctor the bytes."""
    src = Path(path).read_text() if path else text
    out = []
    for line in src.splitlines():
        mm = INSN.match(line)
        if mm:
            out.append((int(mm.group(1), 16), mm.group(3).strip(), mm.group(2).strip()))
    return out


def decoded(mem, begin, end, path=None, vector=VECTOR):
    """Execute the routine's own 63 bytes over `mem` and return eax."""
    ins = instructions(EXCERPT.read_text(), path=path)
    assert ins[0][0] == START and ins[-1][0] < END, "excerpt is not the window"
    m = Machine(mem)
    m.r["%rsi"] = vector
    m.m.store64(vector, begin)
    m.m.store64(vector + 8, end)
    mem.loads = mem.stores = 0        # count only what the routine itself touches
    pc = START
    index = {a: i for i, (a, _, _) in enumerate(ins)}
    i = index[pc]
    while m.steps < m.cap:
        m.steps += 1
        if i >= len(ins):
            break
        a, text, _ = ins[i]
        fields = text.split(None, 1)
        mn = fields[0]
        ops = _split_operands(fields[1]) if len(fields) > 1 and mn != "endbr64" else []
        i += 1
        m.jump_to = None
        r = step(m, mn, ops, text)
        if r == "ret":
            return m.r["%rax"] & 0xFF
        if m.jump_to is not None:
            assert m.jump_to in index, f"jump to 0x{m.jump_to:x} outside the window"
            i = index[m.jump_to]
    raise AssertionError(f"no terminator in {m.steps} steps")


# --------------------------------------------------------------------------- #
# closed-form model
# --------------------------------------------------------------------------- #
def model(mem, begin, end):
    """n = (end - begin) >> 3; return the first non-zero flag byte, else 0.

    Precondition (asserted, not assumed): `end >= begin`.  The binary computes a
    *signed* element count and compares it with an unsigned `jae`, so a vector
    whose `end` precedes its `begin` would make the walk unsigned-huge; that is
    `std::vector` impossibility, not a behaviour to model.
    """
    if end < begin:
        raise ValueError("end < begin is not a valid vector")
    n = (end - begin) >> 3                       # sar $0x3
    if end == begin:                             # je 0x5d9a3cb
        return 0
    i = 0
    while True:
        f = mem.load64(begin + ELEMENT_SIZE * i)
        b = mem.load8(f + FLAG_OFFSET)
        if b != 0:
            return b
        i += 1
        if i >= n:
            return b                             # the last flag byte, which was 0


def build_mem(flags, elem_base=ELEMS, node_base=NODES, vector=VECTOR):
    """Stage a vector of `len(flags)` elements with the given flag bytes."""
    mem = Memory()
    n = len(flags)
    mem.store64(vector, elem_base)
    mem.store64(vector + 8, elem_base + ELEMENT_SIZE * n)
    mem.store64(vector + 16, elem_base + ELEMENT_SIZE * n)
    for i, f in enumerate(flags):
        node = node_base + 0x100 * i
        mem.store64(elem_base + ELEMENT_SIZE * i, node)
        if f:
            mem.store8(node + FLAG_OFFSET, f)
    return mem


def begin_end(flags, elem_base=ELEMS):
    n = len(flags)
    return elem_base, elem_base + ELEMENT_SIZE * n


def agree(flags, path=None):
    mem = build_mem(flags)
    b, e = begin_end(flags)
    want = model(mem, b, e)
    got = decoded(mem, b, e, path=path)
    return want == got, want, got


# --------------------------------------------------------------------------- #
# ledger
# --------------------------------------------------------------------------- #
def generate_cases(seed=7):
    """Return (family, flags) rows: boundaries verbatim, then breadth."""
    cases = [("empty", ())]
    cases += [("clear", tuple([0] * n)) for n in (1, 2, 3, 4, 5, 8, 16, 33, 64, 128)]
    for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 33, 64, 65):
        for pos in range(n):
            cases.append(("position", tuple(1 if i == pos else 0 for i in range(n))))
    for n in (6, 7, 8, 9, 16, 33, 64, 65):
        cases.append(("last", tuple([0] * (n - 1) + [1])))
        cases.append(("last-value", tuple([0] * (n - 1) + [0xFF])))
    for v in (1, 2, 3, 0x80, 0xFF):
        for n in (3, 4):
            cases.append(("value", tuple([0, v, 0][:n])))
    for n in (4, 5, 8, 16):
        cases.append(("dense", tuple([1] * n)))
        cases.append(("alternating", tuple(i % 2 for i in range(n))))
        cases.append(("first-wins", tuple(3 if i == 0 else 7 for i in range(n))))
    for n in (1, 2, 3, 4, 5):                       # every subset of a short vector
        for mask in range(1 << n):
            cases.append(("subset", tuple((mask >> i) & 1 for i in range(n))))
    return cases[:300]


def accesses(flags=(0, 1, 0)):
    """Memory effect of the routine itself (argument staging is not counted)."""
    mem = build_mem(flags)
    b, e = begin_end(flags)
    m = Machine(mem)
    m.r["%rsi"] = VECTOR
    mem.store64(VECTOR, b)
    mem.store64(VECTOR + 8, e)
    mem.loads = mem.stores = 0
    ins = instructions(EXCERPT.read_text())
    index = {a: i for i, (a, _, _) in enumerate(ins)}
    i = index[START]
    steps = 0
    while steps < m.cap:
        steps += 1
        a, text, _ = ins[i]
        fields = text.split(None, 1)
        mn = fields[0]
        ops = _split_operands(fields[1]) if len(fields) > 1 and mn != "endbr64" else []
        i += 1
        m.jump_to = None
        if step(m, mn, ops, text) == "ret":
            break
        if m.jump_to is not None:
            i = index[m.jump_to]
    return {"loads": mem.loads, "stores": mem.stores, "steps": steps,
            "eax": m.r["%rax"] & 0xFF}


def main():
    cases = generate_cases(seed=7)
    disagreements = 0
    for family, flags in cases:
        ok, want, got = agree(flags)
        if not ok:
            disagreements += 1
            print(f"DISAGREE {family} {flags}: model {want} decoded {got}")
    text = ["family\tn\tflags\tmodel\tdecoded\tagree"]
    for family, flags in cases:
        ok, want, got = agree(flags)
        text.append(f"{family}\t{len(flags)}\t{','.join(map(str, flags))}\t{want}\t{got}\t"
                    f"{'yes' if ok else 'NO'}")
    (PACKET / "cases.tsv").write_text("\n".join(text) + "\n")
    a = accesses((0, 1, 0))
    print(f"ledger rows: {len(cases)}; disagreements: {disagreements}; "
          f"routine memory effect on (0,1,0): {a['loads']} loads / {a['stores']} stores "
          f"in {a['steps']} steps; instruction kinds handled: {len(_HANDLED)}")
    (PACKET / "accesses.tsv").write_text(
        "# memory effect of the routine itself, argument staging excluded\n"
        f"loads\t{a['loads']}\nstores\t{a['stores']}\nsteps\t{a['steps']}\n"
        "# instruction kinds the interpreter implements\n"
        + "".join(f"{k}\n" for k in sorted(_HANDLED)))
    return 0 if disagreements == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
