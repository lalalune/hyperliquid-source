#!/usr/bin/env python3
"""Independent reconstruction of `_ZN7rocksdb6DBImpl14GetBGJobLimitsEiiib`
(node #115, 0x5dd5f00..0x5dd5f5b, 91 bytes).

The routine is a leaf that touches no memory at all: it reads four register
arguments and returns a `std::pair<int,int>` packed by the psABI into the single
INTEGER eightbyte register `rax` (low dword = first field, high dword = second).

Recovered semantics (model below, `get_bg_job_limits`):

    if flushes == -1 and compactions == -1:      # kDefault, i.e. unspecified
        f = jobs >> 2 if jobs > 7 else 1         # arithmetic shift = signed /4
        c = jobs - f
        if c <= 0: c = 1
    else:
        f = flushes if flushes > 0 else 1        # the -1 (kDefault) and
        c = compactions if compactions > 0 else 1  #  0 cases both clamp to 1
    if not multi_db: c = 1                       # single-db forces one compaction
    return f, c

Everything here is re-derived from the routine's own bytes: the instruction
stream is decoded from the artifact, and `decoded()` executes those bytes on a
small register machine that raises on any instruction it does not implement, so
the model and the machine are two independent paths to the same answer.

Owned by research/work-items/RE-002-node115-rocksdb-get-bg-job-limits-5dd5f00-115.
"""
from __future__ import annotations

import random
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-get-bg-job-limits-5dd5f00-115")

SYMBOL = "_ZN7rocksdb6DBImpl14GetBGJobLimitsEiiib"
START = 0x5DD5F00
END = 0x5DD5F5B
SIZE = END - START                      # 91

M8 = 0xFF
M16 = 0xFFFF
M32 = 0xFFFFFFFF
M64 = 0xFFFFFFFFFFFFFFFF
MASK = {8: M8, 16: M16, 32: M32, 64: M64}

K_DEFAULT = -1                          # kDefault: "leave this to the derivation"

#: the two dwords the psABI packs into the returned eightbyte
LAYOUT = {"flushes": (0, 32), "compactions": (32, 32)}


# --------------------------------------------------------------------------
# the instruction stream (decoded from the committed objdump excerpt)
# --------------------------------------------------------------------------
def instruction_stream(path=None):
    """The routine's instructions, decoded from the packet's committed objdump
    excerpt (or `path`), each with its raw bytes."""
    text = (Path(path) if path else PACKET / "main.txt").read_text()
    insns = []
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\t?(.*)$", line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        raw = bytes.fromhex(m.group(2).strip())
        body = m.group(3).split("#")[0].strip()
        if not body:
            # objdump prints the last byte of an over-long padding nop on its
            # own line, with no mnemonic: it belongs to the instruction above.
            if insns and insns[-1].end() == addr:
                insns[-1].raw += raw
            continue
        parts = body.split(None, 1)
        insns.append(Ins(addr, raw, parts[0],
                         parts[1] if len(parts) > 1 else ""))
    return insns


class Ins:
    __slots__ = ("addr", "raw", "mnemonic", "op_str")

    def __init__(self, addr, raw, mnemonic, op_str):
        self.addr = addr
        self.raw = raw
        self.mnemonic = mnemonic
        self.op_str = op_str

    def end(self):
        return self.addr + len(self.raw)

    def __repr__(self):
        return f"<{self.addr:#x} {self.mnemonic} {self.op_str}>"


def split_ops(text):
    """Split an objdump operand list on commas that are not inside () or []."""
    out, depth, cur = [], 0, ""
    for ch in text:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


_W = {
    "rax": 64, "rcx": 64, "rdx": 64, "rbx": 64, "rsp": 64, "rbp": 64,
    "rsi": 64, "rdi": 64, "r8": 64, "r9": 64, "r10": 64, "r11": 64,
    "r12": 64, "r13": 64, "r14": 64, "r15": 64,
    "eax": 32, "ecx": 32, "edx": 32, "ebx": 32, "esp": 32, "ebp": 32,
    "esi": 32, "edi": 32, "r8d": 32, "r9d": 32, "r10d": 32, "r11d": 32,
    "r12d": 32, "r13d": 32, "r14d": 32, "r15d": 32,
    "ax": 16, "cx": 16, "dx": 16, "bx": 16, "si": 16, "di": 16,
    "al": 8, "cl": 8, "dl": 8, "bl": 8, "sil": 8, "dil": 8, "spl": 8,
    "bpl": 8, "r8b": 8, "r9b": 8, "r10b": 8, "r11b": 8, "r12b": 8,
    "r13b": 8, "r14b": 8, "r15b": 8, "ah": 8, "ch": 8, "dh": 8, "bh": 8,
}
_CANON = {}
for _base in ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"):
    for _name in _W:
        if _name.startswith(_base[:2]) or _name == _base:
            _CANON.setdefault(_name, _base)
_CANON.update({
    "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
    "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
    "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
    "esi": "rsi", "si": "rsi", "sil": "rsi",
    "edi": "rdi", "di": "rdi", "dil": "rdi",
})
for _n in range(8, 16):
    _CANON[f"r{_n}d"] = f"r{_n}"
    _CANON[f"r{_n}b"] = f"r{_n}"

_IMM = re.compile(r"^\$(-?0x[0-9a-f]+|-?\d+)$")
_HIGH_BYTE = {"ah": 8, "ch": 8, "dh": 8, "bh": 8}

#: every mnemonic this packet implements. Anything else raises, on purpose.
_HANDLED = (
    "endbr64", "nop", "nopw", "nopl", "mov", "movabs", "lea", "add", "sub",
    "or", "xor", "and", "imul", "shl", "sal", "shr", "sar", "cmp", "test",
    "movzbl", "movzwl", "movsbl", "movslq", "cmove", "cmovne", "cmovg",
    "cmovge", "cmovl", "cmovle", "cmova", "cmovae", "cmovb", "cmovbe",
    "je", "jne", "jg", "jge", "jl", "jle", "ja", "jae", "jb", "jbe", "jmp",
    "ret",
)
_COND = {
    "e": lambda f: f["zf"], "ne": lambda f: not f["zf"],
    "g": lambda f: not f["zf"] and f["sf"] == f["of"],
    "ge": lambda f: f["sf"] == f["of"],
    "l": lambda f: f["sf"] != f["of"],
    "le": lambda f: f["zf"] or f["sf"] != f["of"],
    "a": lambda f: not f["cf"] and not f["zf"],
    "ae": lambda f: not f["cf"],
    "b": lambda f: f["cf"],
    "be": lambda f: f["cf"] or f["zf"],
}


def _reg(name):
    """('rax', 32) for '%eax'; raises for a memory operand or an unknown name."""
    if not name.startswith("%") or "(" in name or "[" in name:
        raise NotImplementedError(f"memory operand: {name}")
    n = name[1:]
    if n not in _CANON:
        raise NotImplementedError(f"unknown register: {name}")
    return _CANON[n], _W[n]


def _signed(v, width):
    v &= MASK[width]
    return v - (1 << width) if v & (1 << (width - 1)) else v


class Machine:
    """A 64-bit register machine with the four flags the routine tests."""

    def __init__(self):
        self.regs = {r: 0 for r in ("rax", "rcx", "rdx", "rbx", "rsp",
                                    "rbp", "rsi", "rdi")}
        self.regs.update({f"r{i}": 0 for i in range(8, 16)})
        self.flags = {"zf": False, "sf": False, "of": False, "cf": False}
        self.steps = 0
        self.trace = []

    def read(self, name):
        base, width = _reg(name)
        v = self.regs[base] >> (8 if name[1:] in _HIGH_BYTE else 0)
        return v & MASK[width]

    def write(self, name, value):
        base, width = _reg(name)
        if name[1:] in _HIGH_BYTE:
            raise NotImplementedError("high-byte write")
        if width == 64:
            self.regs[base] = value & M64
        elif width == 32:
            self.regs[base] = value & M32          # 32-bit writes zero-extend
        elif width == 16:
            self.regs[base] = (self.regs[base] & ~M16) | (value & M16)
        else:
            self.regs[base] = (self.regs[base] & ~M8) | (value & M8)
        return self.regs[base]

    # --- flags ------------------------------------------------------------
    def flags_logic(self, res, width):
        res &= MASK[width]
        self.flags.update(zf=res == 0,
                          sf=bool(res & (1 << (width - 1))),
                          of=False, cf=False)

    def flags_sub(self, a, b, res, width):
        m = MASK[width]
        a, b, res = a & m, b & m, res & m
        sign = 1 << (width - 1)
        self.flags.update(zf=res == 0, sf=bool(res & sign), cf=a < b,
                          of=bool(((a ^ b) & (a ^ res)) & sign))

    def cond(self, cc):
        return _COND[cc](self.flags)


def _num(text):
    """An objdump immediate: `$0x1`, `$0xffffffff`, `$-1`."""
    return int(text[1:], 0)


def _execute(m, path=None, limit=256):
    """Execute the routine's own instructions on `m` until `ret`."""
    insns = instruction_stream(path)
    at = {i.addr: k for k, i in enumerate(insns)}
    pc = 0
    while pc < len(insns):
        ins = insns[pc]
        m.steps += 1
        if m.steps > limit:
            raise AssertionError("step limit exceeded")
        mn = ins.mnemonic
        ops = split_ops(ins.op_str) if ins.op_str else []
        m.trace.append(ins)
        if mn not in _HANDLED:
            raise NotImplementedError(f"{ins.addr:#x}: {mn} {ins.op_str}")
        nxt = pc + 1
        if mn in ("endbr64", "nop", "nopw", "nopl"):
            pass
        elif mn == "ret":
            return m
        elif mn in ("mov", "movabs"):
            src = ops[0]                       # AT&T: source, then destination
            imm = _IMM.match(src)
            m.write(ops[1], _num(src) if imm else m.read(src))
        elif mn in ("movzbl", "movzwl", "movsbl", "movslq"):
            src = m.read(ops[0])
            if mn == "movzbl":
                src &= M8
            elif mn == "movzwl":
                src &= M16
            else:
                w = 8 if mn == "movsbl" else 32
                src = _signed(src, w)
            m.write(ops[1], src)
        elif mn in ("add", "sub", "or", "xor", "and", "imul"):
            dst = ops[1]
            a = m.read(dst)
            imm = _IMM.match(ops[0])
            b = _num(ops[0]) if imm else m.read(ops[0])
            width = _reg(dst)[1]
            if mn == "add":
                res = a + b
            elif mn == "sub":
                res = a - b
            elif mn == "or":
                res = a | b
            elif mn == "xor":
                res = a ^ b
            elif mn == "and":
                res = a & b
            else:
                res = _signed(a, width) * _signed(b, width)
            if mn == "add":
                m.flags_sub(a, -b & MASK[width], res, width)
            elif mn == "sub":
                m.flags_sub(a, b, res, width)
            else:
                m.flags_logic(res, width)
            m.write(dst, res)
        elif mn in ("shl", "sal", "shr", "sar"):
            dst = ops[1]
            width = _reg(dst)[1]
            cnt = _num(ops[0]) & 0x3F
            a = m.read(dst)
            if mn in ("shl", "sal"):
                res = a << cnt
            elif mn == "shr":
                res = a >> cnt
            else:
                res = _signed(a, width) >> cnt
            m.flags_logic(res, width)
            m.write(dst, res)
        elif mn in ("cmp", "test"):
            imm = _IMM.match(ops[0])
            width = _reg(ops[1])[1] if ops[1].startswith("%") else _reg(ops[0])[1]
            b = _num(ops[0]) if imm else m.read(ops[0])   # source
            a = m.read(ops[1])                            # destination
            if mn == "cmp":
                m.flags_sub(a, b, a - b, width)
            else:
                m.flags_logic(a & b, width)
        elif mn.startswith("cmov"):
            if m.cond(mn[4:]):
                m.write(ops[1], m.read(ops[0]))
        elif mn.startswith("j"):
            if mn == "jmp" or m.cond(mn[1:]):
                tgt = int(ops[0].split()[0], 16)
                if tgt not in at:
                    raise NotImplementedError(f"branch outside the window: {ops[0]}")
                nxt = at[tgt]
        elif mn == "lea":
            raise NotImplementedError(f"lea: {ins.op_str}")
        pc = nxt
    raise AssertionError("fell off the end of the window without ret")


# --------------------------------------------------------------------------
# the model (recovered semantics)
# --------------------------------------------------------------------------
def _i32(v):
    return v & M32


def s32(v):
    return _signed(v, 32)


def get_bg_job_limits(flushes, compactions, jobs, multi_db):
    """The recovered policy. All four inputs are the C arguments; the result is
    `(flushes, compactions)` as two 32-bit values (see `pack` for the layout).

    `-1` is rocksdb's `kDefault`: 'derive this one'. The derivation only runs
    when *both* counts are `kDefault`; otherwise each count that is not positive
    (including `kDefault`, or a literal 0) clamps to 1. `multi_db == false`
    forces the compaction count to 1 whatever the other rules produced.
    """
    f, c, j = _i32(flushes), _i32(compactions), _i32(jobs)
    if f == _i32(K_DEFAULT) and c == _i32(K_DEFAULT):
        g = s32(j >> 2) if s32(j) > 7 else 1
        k = _i32(j - g)
        if s32(k) <= 0:
            k = 1
    else:
        g = f if s32(f) > 0 else 1
        k = c if s32(c) > 0 else 1
    if not multi_db:
        k = 1
    return _i32(g), _i32(k)


def pack(flushes, compactions):
    """The psABI packing of `std::pair<int,int>`: both INTEGER-class dwords fit
    in one eightbyte, so `rax[31:0]` is the first field and `rax[63:32]` the
    second."""
    return ((_i32(compactions)) << 32) | _i32(flushes)


def unpack_flushes(packed):
    return packed & M32


def unpack_compactions(packed):
    return (packed >> 32) & M32


def _args(m, flushes, compactions, jobs, multi_db):
    m.write("%edi", flushes)
    m.write("%esi", compactions)
    m.write("%edx", jobs)
    m.write("%ecx", 1 if multi_db else 0)
    m.write("%eax", 0xDEADBEEF)      # sentinel: the routine must overwrite it


def decoded_packed(flushes, compactions, jobs, multi_db, path=None):
    """The same question answered by executing the routine's own bytes."""
    m = Machine()
    _args(m, flushes, compactions, jobs, multi_db)
    _execute(m, path=path)
    return m.regs["rax"]


def decoded(flushes, compactions, jobs, multi_db, path=None):
    p = decoded_packed(flushes, compactions, jobs, multi_db, path=path)
    return unpack_flushes(p), unpack_compactions(p)


def model_packed(flushes, compactions, jobs, multi_db):
    f, c = get_bg_job_limits(flushes, compactions, jobs, multi_db)
    return pack(f, c)


def agree(args, path=None):
    return model_packed(*args) == decoded_packed(*args, path=path)


def accesses(path=None):
    """Every memory operand in the window. The routine is a pure register
    function: the claim is that there is none, and this raises if one appears."""
    insns = instruction_stream(path)
    checked = 0
    for ins in insns:
        if ins.mnemonic in ("nop", "nopw", "nopl") or not ins.op_str:
            continue
        checked += 1
        for op in split_ops(ins.op_str):
            if "(" in op or "[" in op:
                raise AssertionError(
                    f"{ins.addr:#x}: unexpected memory operand in {op}")
    return {"loads": [], "stores": [], "non_nop_instructions_checked": checked}


# --------------------------------------------------------------------------
# cases, ledger and evidence tables
# --------------------------------------------------------------------------
INT_MIN = -(1 << 31)
INT_MAX = (1 << 31) - 1
FAMILIES = ("derived", "flushes_default", "explicit", "single_db", "extreme")

#: boundary rows kept verbatim in the ledger (every rule edge this packet claims)
BOUNDARY_CASES = {
    "derived": [
        (K_DEFAULT, K_DEFAULT, j, True)
        for j in (-2, -1, 0, 1, 6, 7, 8, 9, 15, 16, 24, 28, 29, 1000,
                  INT_MAX, INT_MIN)
    ] + [(K_DEFAULT, K_DEFAULT, 8, False), (K_DEFAULT, K_DEFAULT, 0, False)],
    "flushes_default": [
        (K_DEFAULT, c, j, True)
        for c in (-2, -1, 0, 1, 2, 8, INT_MAX) for j in (0, 8, 24)
    ] + [(K_DEFAULT, 3, 24, False), (K_DEFAULT, 0, 24, False)],
    "explicit": [
        (f, c, 0, True)
        for f in (-1, 0, 1, 2, INT_MAX) for c in (-1, 0, 1, 2, INT_MAX)
    ],
    "single_db": [
        (K_DEFAULT, K_DEFAULT, 24, False), (K_DEFAULT, K_DEFAULT, 8, False),
        (2, 4, 0, False), (2, 4, 0, True), (0, 0, 0, False), (-1, 5, 0, False),
    ],
    "extreme": [
        (INT_MIN, INT_MIN, INT_MIN, True), (INT_MAX, INT_MAX, INT_MAX, True),
        (INT_MIN, INT_MAX, 0, True), (INT_MAX, INT_MIN, 0, False),
        (K_DEFAULT, INT_MIN, INT_MAX, True), (K_DEFAULT, INT_MAX, INT_MIN, False),
    ],
}
LEDGER_PER_FAMILY = 60


def _draw(rng, family):
    """A random argument tuple in the family's region."""
    pick = lambda: rng.choice([K_DEFAULT, K_DEFAULT, 0, 1, 2, 3, 4, 8, 16,
                               24, 64, INT_MAX, INT_MIN, rng.randint(-4, 40)])
    j = rng.choice([K_DEFAULT, 0, 1, 7, 8, 9, 12, 16, 24, 32, 64,
                    rng.randint(-8, 128), INT_MAX, INT_MIN])
    if family == "derived":
        return (K_DEFAULT, K_DEFAULT, j, rng.random() < 0.5)
    if family == "flushes_default":
        return (K_DEFAULT, pick(), j, rng.random() < 0.5)
    if family == "explicit":
        return (pick(), pick(), 0, rng.random() < 0.5)
    if family == "single_db":
        return (pick(), pick(), j, False)
    return (rng.choice([INT_MIN, INT_MAX, K_DEFAULT, 0, 1]),
            rng.choice([INT_MIN, INT_MAX, K_DEFAULT, 0, 1]), j,
            rng.random() < 0.5)


def generate_cases(seed=115):
    """Boundary rows verbatim first, then a seeded stratified draw per family
    until every family holds LEDGER_PER_FAMILY rows."""
    rng = random.Random(seed)
    rows = []
    for family in FAMILIES:
        room = LEDGER_PER_FAMILY - len(BOUNDARY_CASES[family])
        assert room >= 0, family
        for args in BOUNDARY_CASES[family]:
            rows.append((family, args))
        for _ in range(room):
            rows.append((family, _draw(rng, family)))
    return rows


def ledger_rows(rows=None):
    """The ledger: each row carries the model's answer and the answer the
    decoded instruction stream produced, so a disagreement is visible."""
    out = []
    for n, (family, (f, c, j, multi)) in enumerate(rows or generate_cases(), 1):
        mf, mc = get_bg_job_limits(f, c, j, multi)
        dp = decoded_packed(f, c, j, multi)
        out.append({
            "id": n, "family": family,
            "flushes": f, "compactions": c, "jobs": j,
            "multi_db": int(bool(multi)),
            "flushes_out": mf, "compactions_out": mc,
            "packed": pack(mf, mc), "decoded": dp,
            "agree": pack(mf, mc) == dp,
            "unpack_signed": (s32(dp >> 32), dp & M32),
        })
    return out


def cases_tsv_rows(rows=None):
    cols = ("id", "family", "flushes", "compactions", "jobs", "multi_db",
            "flushes_out", "compactions_out", "packed", "decoded", "agree")
    out = ["\t".join(cols)]
    for r in rows if rows is not None else ledger_rows():
        out.append("\t".join(
            str(r[c]) if c not in ("packed", "decoded") else hex(r[c])
            for c in cols))
    return out


def replay_case(case):
    """Re-answer one `(flushes, compactions, jobs, multi_db)` tuple."""
    return model_packed(*case), decoded_packed(*case)


def sweep():
    """Exhaustive-ish grid: every rule edge and their neighbourhood."""
    bad = []
    for f in (K_DEFAULT, -2, 0, 1, 2, 3, 8, 64, INT_MAX, INT_MIN):
        for c in (K_DEFAULT, -2, 0, 1, 2, 3, 8, 64, INT_MAX, INT_MIN):
            for j in (K_DEFAULT, -2, -1, 0, 1, 2, 6, 7, 8, 9, 10, 16, 24, 32,
                      64, INT_MAX, INT_MIN):
                for multi in (False, True):
                    if not agree((f, c, j, multi)):
                        bad.append((f, c, j, multi))
    return bad


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    rows = ledger_rows()
    text = "\n".join(cases_tsv_rows(rows)) + "\n"
    (PACKET / "cases.tsv").write_text(text)
    bad = [r for r in rows if not r["agree"]]
    print(f"cases.tsv: {len(rows)} rows ({len(bad)} disagreements)")
    for family in FAMILIES:
        n = sum(1 for r in rows if r["family"] == family)
        assert n == LEDGER_PER_FAMILY, (family, n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
