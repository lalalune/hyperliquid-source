"""Model of node #115 rocksdb MaxFileSizeForLevel 0x607f450..0x607f48a.

MaxFileSizeForLevel picks a configured max file size for a compaction
level out of the level-indexed table the options struct points at. It is
a leaf: it calls nothing, allocates nothing, stores nothing, and reads
exactly one table entry.

Mangled symbol (from the vendor census):
  _ZN7rocksdb19MaxFileSizeForLevelERKNS_16MutableCFOptionsEiNS_15CompactionStyleEib
i.e. rocksdb::MaxFileSizeForLevel(MutableCFOptions const&, int,
CompactionStyle, int, bool).

Argument registers, read off the disassembly:

  rdi  options   (the routine only reads options+0x1e0: a table pointer)
  esi  level
  edx  style
  ecx  base
  r8b  flag

Observable result, pinned from the instructions:

  idx = level
  if level >= base and (style & 0xff) == 0 and (flag & 0xff) == 1:
      idx = level - base            # computed in 32 bits, sign-extended
  result = table[idx]               # table = *(uint64_t **)(options + 0x1e0)

Three details the disassembly pins that a plain reading of the source
would miss:

1. `test %dil,%dil` (0x607f465) tests only the **low byte** of `style`:
   the style test is `(style & 0xff) != 0`, not `style != 0`. A style of
   256 takes the subtraction path.
2. `cmp $0x1,%r8b` (0x607f471) compares only the **low byte** of flag.
3. `sub %ecx,%esi` / `movslq %esi,%rsi` (0x607f480, 0x607f482) compute
   the index in 32 bits and sign-extend it. The branch structure makes
   that value non-negative whenever it is taken (it is only reached when
   level >= base), so no negative index is reachable.

Domain: the model requires the table to hold the selected index. The
routine indexes `table[idx]` with no bound check of its own -- the bound
is the caller's, which is why the model takes the table and rejects an
index outside it instead of guessing.

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Vendor census member d7ece8bd5f9dc186-cf_options.o, rlib
liblibrocksdb_sys-b032f986857674dc.rlib, crate librocksdb-sys,
candidate version 0.11.0+8.1.1, native true,
target_body_sha256 == source_body_sha256 (raw equal), no relocations,
3 identical source copies.

Environment limits: static disassembly only (objdump/readelf on the
digest-verified local binary). No cargo/rustc, Ghidra or a live node was
used; this is a Python transcription of the pinned algorithm, not a build
of node or rocksdb code. The 10 direct callers are recorded in the
packet's callers.tsv.
"""

import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-max-file-size-for-level-607f450-115")

START = 0x607f450
END = 0x607f48A
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

OPTIONS_TABLE_OFFSET = 0x1E0
M32 = (1 << 32) - 1


def _index(level, style, base, flag):
    """The selected table index, exactly as the routine computes it."""
    if level >= base and (style & 0xFF) == 0 and (flag & 0xFF) == 1:
        idx = (level - base) & M32          # sub %ecx,%esi
        if idx >= 1 << 31:                  # movslq %esi,%rsi
            idx -= 1 << 32
        return idx
    return level


def max_file_size_for_level(table, level, style, base, flag):
    """The value the routine returns: table[index(level, style, base, flag)].

    Raises IndexError when the selected index is not a valid index into
    `table` -- the routine itself does not bound-check (see the model
    docstring), so an out-of-range index is outside the characterized
    domain rather than a value.
    """
    idx = _index(level, style, base, flag)
    if not isinstance(idx, int) or not 0 <= idx < len(table):
        raise IndexError(f"index {idx} outside a table of {len(table)} entries")
    return table[idx]


# ---------------------------------------------------------------------------
# Decoded execution of the routine's own bytes, for cross-checking the
# closed form. This interprets the committed instruction stream (main.txt,
# whose bytes verify.py hashes against the binary) on a small machine
# model, so the check runs against the target's instructions rather than
# against a second restatement of the same prose.
# ---------------------------------------------------------------------------

import re

import capstone

LINE = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*(\S.*)$")


def instruction_stream(path=None):
    """[(address, bytes, mnemonic, op_str)] from the committed excerpt."""
    path = path or (PACKET / "main.txt")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    out = []
    for line in Path(path).read_text().splitlines():
        m = LINE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        raw = bytes.fromhex(m.group(2).strip().replace(" ", ""))
        ins = next(iter(md.disasm(raw, addr)))
        assert ins.size == len(raw), hex(addr)
        out.append(ins)
    return out


def max_file_size_for_level_decoded(table, level, style, base, flag,
                                    options=0x2000, table_at=0x3000):
    """Run the routine's decoded instructions on a tiny machine model.

    Registers the routine uses plus a flat memory: the options struct at
    `options` (its +0x1e0 slot holds `table_at`) and the table itself as
    64-bit entries. Only the instruction set this routine uses is
    implemented; anything else raises, so a changed decode cannot pass.
    """
    regs = {n: 0 for n in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8",
                           "r9", "r10", "r11", "r12", "r13", "r14", "r15")}
    mem = {}
    for i, v in enumerate(table):
        mem[table_at + 8 * i] = v & ((1 << 64) - 1)
    mem[options + OPTIONS_TABLE_OFFSET] = table_at
    regs["rdi"] = options
    regs["rsi"] = level & M32      # esi
    regs["rdx"] = style & M32      # edx
    regs["rcx"] = base & M32       # ecx
    regs["r8"] = flag & 0xFF       # r8b
    flags = {"zf": False, "sf": False}
    R64 = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
           "r12", "r13", "r14", "r15"}
    R32 = {"eax": "rax", "ecx": "rcx", "edx": "rdx", "esi": "rsi",
           "edi": "rdi", "r8d": "r8"}
    R8 = {"al": "rax", "cl": "rcx", "dl": "rdx", "dil": "rdi", "r8b": "r8"}
    pc = 0
    insns = instruction_stream()
    steps = 0
    while pc < len(insns):
        steps += 1
        assert steps <= 200, "runaway decode"
        ins = insns[pc]
        m, ops = ins.mnemonic, ins.operands
        if m in ("endbr64", "nop", "nopl", "nopw"):
            pc += 1
            continue
        if m == "ret":
            return regs["rax"]
        if m.startswith("j"):
            take = {"jne": not flags["zf"], "je": flags["zf"]}.get(m)
            assert take is not None, m
            if take:
                pc = next(i for i, x in enumerate(insns)
                          if x.address == ops[0].imm)
            else:
                pc += 1
            continue
        if m in ("cmp", "test", "sub", "or", "setl", "setne", "mov",
                 "movslq", "movsxd", "push", "xor"):
            pass
        else:
            raise AssertionError(f"unhandled instruction {m} at {hex(ins.address)}")
        if m == "cmp":
            size = ops[0].size
            a = _reg(regs, ops[0], R64, R32, R8) & ((1 << (8 * size)) - 1)
            if ops[1].type == capstone.x86.X86_OP_IMM:
                b = ops[1].imm & ((1 << (8 * size)) - 1)
            else:
                b = _reg(regs, ops[1], R64, R32, R8) & ((1 << (8 * size)) - 1)
            d = a - b
            flags["zf"] = (d & ((1 << (8 * size)) - 1)) == 0
            flags["sf"] = bool(d & (1 << (8 * size - 1)))
            pc += 1
            continue
        if m == "test":
            a = _reg(regs, ops[0], R64, R32, R8)
            b = _reg(regs, ops[1], R64, R32, R8)
            d = (a & b) & ((1 << (8 * ops[0].size)) - 1)
            flags["zf"] = d == 0
            flags["sf"] = bool(d & (1 << (8 * ops[0].size - 1)))
            pc += 1
            continue
        if m == "or":
            d = _reg(regs, ops[0], R64, R32, R8) | _reg(regs, ops[1], R64, R32, R8)
            d &= (1 << (8 * ops[0].size)) - 1
            _set(regs, ops[0], d, R64, R32, R8)
            flags["zf"] = d == 0
            flags["sf"] = bool(d & (1 << (8 * ops[0].size - 1)))
            pc += 1
            continue
        if m == "sub":
            a = _reg(regs, ops[0], R64, R32, R8)
            b = _reg(regs, ops[1], R64, R32, R8)
            size = ops[0].size
            d = (a - b) & ((1 << (8 * size)) - 1)
            _set(regs, ops[0], d, R64, R32, R8)
            flags["zf"] = d == 0
            flags["sf"] = bool(d & (1 << (8 * size - 1)))
            pc += 1
            continue
        if m == "setl":
            d = 1 if flags["sf"] else 0
            _set(regs, ops[0], d, R64, R32, R8)
            pc += 1
            continue
        if m == "setne":
            d = 0 if flags["zf"] else 1
            _set(regs, ops[0], d, R64, R32, R8)
            pc += 1
            continue
        if m in ("movslq", "movsxd"):
            src = _reg(regs, ops[0], R64, R32, R8)
            v = src & M32
            if v >= 1 << 31:
                v -= 1 << 32
            _set(regs, ops[1], v & ((1 << 64) - 1), R64, R32, R8)
            pc += 1
            continue
        if m == "xor":
            d = _reg(regs, ops[0], R64, R32, R8) ^ _reg(regs, ops[1], R64, R32, R8)
            _set(regs, ops[0], d, R64, R32, R8)
            flags["zf"] = d == 0
            pc += 1
            continue
        if m == "push":
            pc += 1
            continue
        if m == "mov":
            dst, src = ops[0], ops[1]
            if dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_MEM:
                addr = _addr(regs, src, R64)
                v = mem.get(addr, 0)
                _set(regs, dst, v, R64, R32, R8)
            elif dst.type == capstone.x86.X86_OP_REG and src.type == capstone.x86.X86_OP_REG:
                v = _reg(regs, src, R64, R32, R8)
                _set(regs, dst, v, R64, R32, R8)
            else:
                raise AssertionError(f"unhandled mov {ins.op_str}")
            pc += 1
            continue
        raise AssertionError(f"unhandled {m}")
    raise AssertionError("fell off the instruction stream")


def _reg(regs, op, R64, R32, R8):
    name = _name(op.reg)
    assert name in R64 or name in R32 or name in R8, name
    if name in R8:
        return regs[R8[name]] & 0xFF
    if name in R32:
        return regs[R32[name]] & M32
    return regs[name] & ((1 << 64) - 1)


def _set(regs, op, value, R64, R32, R8):
    name = _name(op.reg)
    if name in R8:
        key = R8[name]
        regs[key] = (regs[key] & ~0xFF) | (value & 0xFF)
    elif name in R32:
        key = R32[name]
        regs[key] = value & M32
    else:
        assert name in R64, name
        regs[name] = value & ((1 << 64) - 1)


def _addr(regs, op, R64):
    import capstone as _cs
    import capstone as _cs
    base = regs[_name(op.mem.base)] if op.mem.base != 0 else 0
    index = regs[_name(op.mem.index)] if op.mem.index != 0 else 0
    scale = op.mem.scale or 1
    assert scale in (1, 2, 4, 8), scale
    return base + index * scale + op.mem.disp


def _name(reg_id):
    return {capstone.x86.X86_REG_RAX: "rax", capstone.x86.X86_REG_RBX: "rbx",
            capstone.x86.X86_REG_RCX: "rcx", capstone.x86.X86_REG_RDX: "rdx",
            capstone.x86.X86_REG_RSI: "rsi", capstone.x86.X86_REG_RDI: "rdi",
            capstone.x86.X86_REG_R8: "r8", capstone.x86.X86_REG_EAX: "eax",
            capstone.x86.X86_REG_ECX: "ecx", capstone.x86.X86_REG_EDX: "edx",
            capstone.x86.X86_REG_ESI: "esi", capstone.x86.X86_REG_EDI: "edi",
            capstone.x86.X86_REG_R8D: "r8d",
            capstone.x86.X86_REG_AL: "al", capstone.x86.X86_REG_CL: "cl",
            capstone.x86.X86_REG_DL: "dl", capstone.x86.X86_REG_DIL: "dil",
            capstone.x86.X86_REG_R8B: "r8b"}.get(reg_id, f"reg{reg_id}")


# ---------------------------------------------------------------------------
# Case generation
# ---------------------------------------------------------------------------

def _table(rng, n=8):
    return [rng.randrange(1 << 48) for _ in range(n)]


def generate_cases(seed=115):
    """2,400 deterministic cases: 600 matrix, 600 style, 600 base,
    600 random. Each row is (id, group, param, expected)."""
    rng = random.Random(seed)
    rows = []
    state = {"cell": "structural"}

    def add(cid, group, param):
        table = param["table"]
        got = max_file_size_for_level(table, param["level"], param["style"],
                                      param["base"], param["flag"])
        # The closed form must agree with the decoded execution of the
        # routine's own committed instructions.
        assert got == max_file_size_for_level_decoded(
            table, param["level"], param["style"], param["base"],
            param["flag"]), (cid, param)
        rows.append({"id": cid, "group": group,
                     "param": json.dumps(param, sort_keys=True),
                     "expected": json.dumps({"value": got}),
                     "cell": state["cell"]})

    # --- group 1: matrix (600): the whole branch matrix, both flags ---
    n = [0]

    def mat(param):
        add(f"matrix-{n[0]:04d}", "matrix", param)
        n[0] += 1

    t = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]
    for level in (0, 1, 2, 3, 5):
        for base in (0, 1, 2, 4):
            for style in (0, 1, 2):
                for flag in (0, 1):
                    mat({"table": t, "level": level, "style": style,
                         "base": base, "flag": flag})
    assert n[0] >= 100, n[0]
    state["cell"] = "sweep"
    while n[0] < 600:
        level = rng.randrange(0, 8)
        mat({"table": _table(rng), "level": level,
             "style": rng.choice((0, 1, 2, 7, 255)),
             "base": rng.randrange(0, 9), "flag": rng.choice((0, 1, 2, 255))})
    assert n[0] == 600, n[0]

    # --- group 2: style (600): the low-byte style test ---
    n = [0]
    state["cell"] = "structural"

    def sty(param):
        add(f"style-{n[0]:04d}", "style", param)
        n[0] += 1

    # style 256 / 512 / 0x10000 have a zero low byte: they take the
    # subtraction path even though `style != 0`.
    for style in (256, 512, 0x10000, 0xFFFFFF00, 0x100, 0x1000000):
        for flag in (0, 1):
            for level, base in ((5, 2), (2, 5), (3, 3)):
                sty({"table": t, "level": level, "style": style,
                     "base": base, "flag": flag})
    for style in (1, 255, 0xFF, 257):
        sty({"table": t, "level": 5, "style": style, "base": 2, "flag": 1})
    state["cell"] = "sweep"
    while n[0] < 600:
        style = rng.choice((0, 1, 255, 256, 257, 512, 0x10000,
                            rng.randrange(1 << 32)))
        sty({"table": _table(rng), "level": rng.randrange(0, 8),
             "style": style, "base": rng.randrange(0, 9),
             "flag": rng.choice((0, 1))})
    assert n[0] == 600, n[0]

    # --- group 3: base (600): the subtraction path, level >= base ---
    n = [0]
    state["cell"] = "structural"

    def bas(param):
        add(f"base-{n[0]:04d}", "base", param)
        n[0] += 1

    for base in range(0, 9):
        for level in (base, base + 1, base + 7):
            if level < 8:
                bas({"table": t, "level": level, "style": 0, "base": base,
                     "flag": 1})
        bas({"table": t, "level": max(0, base - 1), "style": 0, "base": base,
             "flag": 1})
    # the flag's low byte only: 257 has low byte 1 (subtract), 256 has 0.
    for flag in (256, 257, 0x10000, 0x10001):
        bas({"table": t, "level": 5, "style": 0, "base": 2, "flag": flag})
    state["cell"] = "sweep"
    while n[0] < 600:
        base = rng.randrange(0, 9)
        bas({"table": _table(rng), "level": rng.randrange(0, 8),
             "style": rng.choice((0, 1)), "base": base,
             "flag": rng.choice((0, 1, 255, 256, 257))})
    assert n[0] == 600, n[0]

    # --- group 4: random (600) ---
    n = [0]
    state["cell"] = "sweep"
    while n[0] < 600:
        add(f"random-{n[0]:04d}", "random",
            {"table": _table(rng), "level": rng.randrange(0, 8),
             "style": rng.randrange(1 << 32), "base": rng.randrange(0, 9),
             "flag": rng.randrange(1 << 16)})
        n[0] += 1
    assert n[0] == 600, n[0]

    assert len(rows) == 2400, len(rows)
    return rows


def replay_case(case):
    """Recompute a case's expected value from its param."""
    param = json.loads(case["param"])
    got = max_file_size_for_level(param["table"], param["level"],
                                  param["style"], param["base"], param["flag"])
    return got == json.loads(case["expected"])["value"], got


LEDGER_PARAM_MAX = 600
LEDGER_TARGET = 300


def _stride(seq, need):
    if need <= 0:
        return []
    if len(seq) <= need:
        return list(seq)
    step = len(seq) / need
    return [seq[int(i * step)] for i in range(need)]


def ledger_rows(rows=None):
    """The committed, human-reviewable ledger: stratified over the four
    case families, structural cells first, then an even stride sample."""
    if rows is None:
        rows = generate_cases()
    pool = [r for r in rows if len(r["param"]) <= LEDGER_PARAM_MAX]
    groups = []
    for r in pool:
        if r["group"] not in groups:
            groups.append(r["group"])
    per = LEDGER_TARGET // max(1, len(groups))
    out = []
    for g in groups:
        sel = [r for r in pool if r["group"] == g]
        structural = [r for r in sel if r.get("cell") == "structural"]
        sweep = [r for r in sel if r.get("cell") != "structural"]
        head = structural[:per // 2]
        head += _stride(sweep, per - len(head))
        out += head
    if len(out) < LEDGER_TARGET:
        have = {r["id"] for r in out}
        rest = [r for r in pool
                if r["id"] not in have and r.get("cell") != "structural"]
        out += _stride(rest, LEDGER_TARGET - len(out))
    return out[:LEDGER_TARGET]


def cases_tsv_rows():
    return ledger_rows()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ["gen-cases"]:
        out = PACKET / "cases.tsv"
        rows = cases_tsv_rows()
        with open(out, "w") as fh:
            fh.write("id\tgroup\tparam\texpected\n")
            for r in rows:
                fh.write("\t".join(r[k] for k in ("id", "group", "param",
                                                  "expected")) + "\n")
        print(f"wrote {out} ({len(rows)} committed cases; the full "
              f"2,400-case sweep is re-derived in memory by the tests)")
        return 0
    print("usage: rocksdb_max_file_size_for_level_607f450_115.py [gen-cases]")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
