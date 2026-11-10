"""Model of node #115 zstd `COVER_sum` 0x62ad5e0..0x62ad641 (97 bytes).

`uint64_t COVER_sum(const size_t* splits, unsigned n)` — zstd's COVER
optimizer sums a slice of a size array:

  result = sum(splits[0:n]) mod 2**64

Behaviour read off the routine's own committed instruction bytes
(`main.txt`, hashed against the digest-verified artifact by `verify.py`):

  test %esi,%esi ; je 0x62ad638        (0x62ad5e4/0x62ad5e6)  n == 0 -> 0
  cmp  $1,%esi  ; je 0x62ad63b         (0x62ad5e8/0x62ad5eb)  n == 1 -> one element
  pxor %xmm0,%xmm0                     (0x62ad5f2)            zero the 2-lane acc
  shr $1,%edx / shl $4,%rdx / add %rdi,%rdx   (0x62ad5f6..0x62ad5fc)
                                        end = splits + 16*(n>>1)
  0x62ad600:  movdqu (%rax),%xmm2       load two u64 splits
              paddq %xmm2,%xmm0         add them as two 64-bit lanes
              cmp %rax,%rdx ; jne       until the end pointer
  movdqa/psrldq $8/paddq               (0x62ad611..0x62ad61a) horizontal fold
  movq %xmm0,%rax                      (0x62ad61e)            low lane
  test $1,%sil ; je                    (0x62ad623/0x62ad627)  odd element?
  and $0xfffffffe,%esi                 (0x62ad629)            index = n & ~1
  add (%rdi,%rsi,8),%rax               (0x62ad62c)            add the tail
  ret / xor %eax,%eax ; ret            (0x62ad630, 0x62ad638)

Four things follow from those bytes and are exercised by the ledger:

1. **The vector loop runs `n >> 1` iterations and covers `2*(n>>1)` elements**,
   so for odd `n` exactly one element is left over; the tail add uses index
   `n & ~1` — the last index — after the horizontal fold.
2. **The `n == 1` case is folded into that same tail add.** Instead of a
   second scalar path, `0x62ad63b` zeroes `%esi` and jumps to `0x62ad62c`, so
   the routine contains exactly one scalar `add` from memory.
3. **The addition is per-64-bit-lane and wraps.** `paddq` adds 64-bit lanes
   with no carry into the neighbouring lane, and the horizontal fold is
   another `paddq`, so the result is the sum modulo 2**64 — the same value a
   wrapping scalar sum produces, independent of element order.
4. **`n == 0` returns zero without touching `splits`** (`%eax` is zeroed at
   `0x62ad638`), so an empty slice is safe.

The body is a leaf with no stores, no calls and no relocations, and the whole
body is one `.eh_frame` FDE. The `splits` loads are the only memory accesses:
the routine never writes.

Callers (3, all inside the FDE `0x62ac520..0x62ac9c9`; see the packet's
`callers.tsv` / `caller_use.tsv`): two copy the sum out of `rax` and one
stores it, so every one of them consumes the returned value.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-zstd-cover-sum-62ad5e0-115")

START = 0x62AD5E0
END = 0x62AD641
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
BASE = 0x1000000                # synthetic address of splits[0] for the model


def cover_sum(splits, n):
    """The closed form: the first `n` elements, summed modulo 2**64."""
    splits = list(splits)
    if not 0 <= n <= len(splits):
        raise IndexError(f"n={n} outside the supplied slice of {len(splits)}")
    return sum(splits[:n]) & M64


LINE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]{2,})\s*(\S.*)?$")


class Ins:
    __slots__ = ("addr", "raw", "mnemonic", "op_str")

    def __init__(self, addr, raw, mnemonic, op_str):
        self.addr = addr
        self.raw = raw
        self.mnemonic = mnemonic
        self.op_str = op_str

    def end(self):
        return self.addr + len(self.raw)

    def __repr__(self):                       # pragma: no cover - debug aid
        return f"<{self.addr:#x} {self.mnemonic} {self.op_str}>"


_STREAM_CACHE = {}


def instruction_stream(path=None):
    """Every `main.txt` line whose address lies inside [START, END).

    objdump wraps a long instruction's bytes onto a continuation line that has
    an address and bytes but no mnemonic; those are folded into the
    instruction they belong to. Memoized: the differential calls this once.
    """
    key = str(path) if path is not None else "<default>"
    if key in _STREAM_CACHE:
        return _STREAM_CACHE[key]
    src = Path(path) if path is not None else (PACKET / "main.txt")
    out = []
    for line in src.read_text().splitlines():
        m = LINE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if not (START <= addr < END):
            continue
        raw = bytes.fromhex(m.group(2).replace(" ", ""))
        if m.group(3) is None:                 # continuation of the previous line
            assert out and out[-1].end() == addr, hex(addr)
            out[-1].raw += raw
            continue
        text = m.group(3).strip()
        parts = text.split(None, 1)
        out.append(Ins(addr, raw, parts[0], parts[1] if len(parts) > 1 else ""))
    _STREAM_CACHE[key] = out
    return out


# --- a small machine model for exactly the instructions this routine uses ---

_WIDTH = {"rax": 64, "eax": 32, "ax": 16, "al": 8,
          "rdx": 64, "edx": 32, "dx": 16, "dl": 8,
          "rcx": 64, "ecx": 32, "cx": 16, "cl": 8,
          "rdi": 64, "edi": 32, "di": 16, "dil": 8,
          "rsi": 64, "esi": 32, "si": 16, "sil": 8,
          "r8": 64, "r8d": 32, "r8b": 8}
_CANON = {"eax": "rax", "ax": "rax", "al": "rax",
          "edx": "rdx", "dx": "rdx", "dl": "rdx",
          "ecx": "rcx", "cx": "rcx", "cl": "rcx",
          "edi": "rdi", "di": "rdi", "dil": "rdi",
          "esi": "rsi", "si": "rsi", "sil": "rsi",
          "r8d": "r8", "r8b": "r8"}
_IMM = re.compile(r"^\$(-?0x[0-9a-f]+|-?\d+)$")
_MEM = re.compile(r"^(?:(0x[0-9a-f]+|-?\d+))?\((%[a-z0-9]+)"
                  r"(?:,(%[a-z0-9]+),(\d+))?\)$")
_XMM = re.compile(r"^%xmm(\d+)$")
_16B = ("movdqu", "movdqa", "movups", "movaps")


def split_ops(text):
    """Split AT&T operands on top-level commas only: `(%rdi,%rsi,8),%rax` is
    two operands, not four."""
    out, depth, cur = [], 0, []
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur).strip())
    return [o for o in out if o]


def _reg(reg):
    reg = reg.strip().lstrip("%")
    if _XMM.match("%" + reg):
        return "xmm" + reg[3:]
    return _CANON.get(reg, reg)


def _width(reg):
    reg = reg.strip().lstrip("%")
    return _WIDTH.get(reg, 128 if reg.startswith("xmm") else 64)


class Machine:
    """Byte-addressed memory plus 64-bit registers and 128-bit xmm lanes."""

    def __init__(self, splits, base=BASE):
        self.mem = {}
        self.regs = {"rax": 0, "rdx": 0, "rcx": 0, "rdi": base, "rsi": 0,
                     "xmm0": 0, "xmm1": 0, "xmm2": 0}
        for i, v in enumerate(splits):
            self.store(base + 8 * i, v & M64, 8)

    # -- memory ------------------------------------------------------------
    def load(self, addr, size):
        out = 0
        for i in range(size):
            b = self.mem.get(addr + i)
            assert b is not None, \
                f"read of uninitialised memory at {addr + i:#x}"
            out |= b << (8 * i)
        return out

    def store(self, addr, value, size):
        for i in range(size):
            self.mem[addr + i] = (value >> (8 * i)) & 0xFF

    # -- operands ----------------------------------------------------------
    def addr_of(self, text):
        m = _MEM.match(text.strip())
        assert m, f"not a memory operand: {text}"
        disp = int(m.group(1), 0) if m.group(1) else 0
        base = self.get(m.group(2))
        if m.group(3):
            base += self.get(m.group(3)) * int(m.group(4))
        return (base + disp) & M64

    def get(self, text):
        text = text.strip()
        if _XMM.match(text):
            return self.regs[_reg(text)] & ((1 << 128) - 1)
        return self.regs[_reg(text)] & M64

    def set(self, text, value):
        text = text.strip()
        name = _reg(text)
        if name.startswith("xmm"):
            self.regs[name] = value & ((1 << 128) - 1)
            return
        # writing a sub-register zero-extends into the 64-bit register
        self.regs[name] = value & ((1 << _width(text)) - 1)


def cover_sum_decoded(splits, n, path=None):
    """Execute COVER_sum's own decoded instructions on a machine model.

    Raises AssertionError on any instruction this model does not implement, so
    it can never agree by accident.
    """
    splits = list(splits)
    insns = instruction_stream(path)
    assert insns, "empty instruction stream"
    by_addr = {i.addr: k for k, i in enumerate(insns)}
    m = Machine(splits)
    m.regs["rsi"] = n & M64
    pc = 0
    flags = {}
    steps = 0
    while True:
        steps += 1
        assert steps <= 1000, "no termination"
        assert pc < len(insns), "ran off the end of the routine"
        ins = insns[pc]
        mn = ins.mnemonic
        ops = split_ops(ins.op_str)
        pc += 1
        if mn in ("endbr64", "nop", "nopl", "nopw", "int3"):
            continue
        if mn in ("test", "cmp"):
            a = _IMM.match(ops[0])
            a = int(a.group(1), 0) & M64 if a else m.get(ops[0])
            b = m.get(ops[1])
            if mn == "test":        # AND: ZF is set when (a & b) == 0
                flags["zf"] = (a & b) == 0
                flags["cf"] = False
            else:                    # CMP a,b computes b - a
                flags["zf"] = ((b - a) & M64) == 0
                flags["cf"] = (b & M64) < (a & M64)
            continue
        if mn == "jmp":
            target = int(ops[0].split()[0], 16)
            assert target in by_addr, (ins, "target outside the routine")
            pc = by_addr[target]
            continue
        if mn in ("je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
                  "jl", "jle", "jg", "jge"):
            zf, cf = flags.get("zf"), flags.get("cf")
            take = {"je": zf, "jz": zf, "jne": not zf, "jnz": not zf,
                    "ja": (not zf) and (not cf), "jae": not cf,
                    "jb": cf, "jbe": cf or zf,
                    "jl": None, "jle": None, "jg": None, "jge": None}[mn]
            assert take is not None, \
                f"signed branch {mn} is not part of this routine"
            if take:
                target = int(ops[0].split()[0], 16)
                assert target in by_addr, (ins, "target outside the routine")
                pc = by_addr[target]
            continue
        if mn in _16B:
            src, dst = ops
            if _MEM.match(src):
                m.set(dst, m.load(m.addr_of(src), 16))
            else:
                m.set(dst, m.get(src))
            continue
        if mn == "movq":
            src, dst = ops
            m.set(dst, m.get(src))
            continue
        if mn == "mov":
            src, dst = ops
            imm = _IMM.match(src)
            if imm:
                m.set(dst, int(imm.group(1), 0))
            elif _MEM.match(src):
                m.set(dst, m.load(m.addr_of(src), _width(dst) // 8))
            else:
                m.set(dst, m.get(src))
            continue
        if mn == "pxor":
            m.set(ops[1], m.get(ops[0]) ^ m.get(ops[1]))
            continue
        if mn == "paddq":
            a, b = m.get(ops[0]), m.get(ops[1])
            out = 0
            for lane in range(2):     # two 64-bit lanes, no carry between
                out |= (((a >> (64 * lane)) + (b >> (64 * lane))) & M64) \
                    << (64 * lane)
            m.set(ops[1], out)
            continue
        if mn == "psrldq":
            m.set(ops[1],
                  m.get(ops[1]) >> (8 * int(_IMM.match(ops[0]).group(1), 0)))
            continue
        if mn in ("add", "sub", "and", "or", "xor", "shl", "shr", "sar"):
            src, dst = ops
            imm = _IMM.match(src)
            if _MEM.match(src):
                s = m.load(m.addr_of(src), _width(dst) // 8)
            elif imm:
                s = int(imm.group(1), 0) & M64
            else:
                s = m.get(src)
            cur = m.get(dst)
            # lazy, so an unused shift never gets evaluated
            if mn == "add":
                out = cur + s
            elif mn == "sub":
                out = cur - s
            elif mn == "and":
                out = cur & s
            elif mn == "or":
                out = cur | s
            elif mn == "xor":
                out = cur ^ s
            elif mn == "shl":
                out = cur << (s & 63)
            else:                       # shr / sar on an unsigned model
                out = cur >> (s & 63)
            m.set(dst, out & M64)
            continue
        if mn == "ret":
            return m.get("rax") & M64
        raise AssertionError(f"unimplemented instruction: {ins}")


# --- cases, ledger and evidence tables -------------------------------------

def _splits(rng, k):
    out = []
    for _ in range(k):
        r = rng.random()
        if r < 0.25:
            out.append(rng.choice([M64, M64 - 1, 1 << 63, (1 << 63) - 1]))
        elif r < 0.5:
            out.append(rng.randrange(1 << 8))
        elif r < 0.75:
            out.append(rng.randrange(1 << 32))
        else:
            out.append(rng.getrandbits(64))
    return out


def generate_cases(seed=115):
    """The full sweep: 2400 cases over four families."""
    import random
    rng = random.Random(seed)
    fams = {}
    # empty: n == 0, the early return
    fams["empty"] = [{"family": "empty", "splits": _splits(rng, 4), "n": 0}
                     for _ in range(600)]
    # single: n == 1, the path folded into the tail add
    fams["single"] = [{"family": "single", "splits": _splits(rng, 3), "n": 1}
                      for _ in range(600)]
    # pairs: n even and >= 2, so only the vector path runs
    fams["pairs"] = [{"family": "pairs", "splits": _splits(rng, 66),
                      "n": 2 * rng.randrange(1, 33)} for _ in range(600)]
    # odd: n odd and >= 3, so the vector path runs and then the tail add
    fams["odd"] = []
    while len(fams["odd"]) < 600:
        k = rng.randrange(3, 67)
        if k % 2:
            fams["odd"].append(
                {"family": "odd", "splits": _splits(rng, k), "n": k})
    out = []
    for name in ("empty", "single", "pairs", "odd"):
        assert len(fams[name]) == 600, (name, len(fams[name]))
        out.extend(fams[name])
    return out


LEDGER_TARGET = 300


def _stride(seq, need):
    assert need <= len(seq), (need, len(seq))
    if need == len(seq):
        return list(seq)
    step = len(seq) / need
    return [seq[int(i * step)] for i in range(need)]


def _short(case):
    """A ledger row keeps arrays short so the committed table stays reviewable."""
    n = case["n"]
    k = min(n, 4) if n else 1
    return {"family": case["family"], "splits": case["splits"][:k], "n": min(n, k)}


def ledger_rows(rows=None):
    """A ~300-case stratified, reviewable subset of the sweep."""
    rows = list(rows) if rows is not None else generate_cases()
    fams = {}
    for r in rows:
        fams.setdefault(r["family"], []).append(_short(r))
    per = LEDGER_TARGET // max(1, len(fams))
    out = []
    for name in sorted(fams):
        out.extend(_stride(fams[name], per))
    for i, r in enumerate(out):
        r = dict(r)
        r["id"] = i + 1
        r["expected"] = cover_sum(r["splits"], r["n"])
        r["tail"] = r["n"] >= 2 and bool(r["n"] & 1)
        out[i] = r
    return out


def replay_case(case):
    return cover_sum(case["splits"], case["n"])


def _fmt(splits):
    return "[" + ",".join(hex(v) for v in splits) + "]"


def cases_tsv_rows():
    rows = ["id\tfamily\tn\tsplits\texpected\twraps\ttail_add"]
    for r in ledger_rows():
        wraps = "1" if sum(r["splits"][:r["n"]]) > M64 else "0"
        rows.append("\t".join([
            str(r["id"]), r["family"], str(r["n"]), _fmt(r["splits"]),
            hex(r["expected"]), wraps, "1" if r["tail"] else "0",
        ]))
    return rows


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "gen-cases":
        path = PACKET / "cases.tsv"
        path.write_text("\n".join(cases_tsv_rows()) + "\n")
        print(f"wrote {path}")
        return 0
    print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
