"""Model of node #115 rocksdb `GetVarint32PtrFallback` 0x61bd4f0..0x61bd53b.

`const char* GetVarint32PtrFallback(const char* p, const char* limit,
                                    uint32_t* value)` - the bounded LEB128
decoder from rocksdb's `util/coding.cc`: decode one varint from `p`, store it
through `value`, and return the position just past the last byte - or nullptr
when it cannot.

Behaviour read off the routine's own committed instruction bytes (`main.txt`,
hashed against the digest-verified artifact by `verify.py`):

  61bd4f7  cmp %rsi,%rdi / jae  0x61bd538   p >= limit            -> nullptr
  61bd51d  movzbl (%rax),%edi / add $0x1,%rax  read a byte, advance the pointer
  61bd524  test %dil,%dil / js  0x61bd508   bit 7 set -> continuation byte
  61bd508  and $0x7f,%edi / shl %cl,%edi / add $0x7,%ecx / or %edi,%r8d
  61bd513  cmp $0x1c,%ecx / ja  0x61bd538   shift > 28            -> nullptr
  61bd518  cmp %rsi,%rax / jae  0x61bd538   pointer reached limit -> nullptr
  61bd529  shl %cl,%edi / or %r8d,%edi / mov %edi,(%rdx)  store, return rax
  61bd538  xor %eax,%eax / ret               nullptr

Four build-specific details follow from those bytes and are exercised by the
ledger:

1. **The bound is checked before the first byte is read, and again after every
   continuation byte.** `p >= limit` returns nullptr immediately (unsigned
   `jae` at 0x61bd4fa), and a varint that runs off the end returns nullptr at
   0x61bd51b - so a truncated varint is rejected rather than answered with the
   bytes seen so far.
2. **The continuation test is the sign bit of the byte just read.** `test
   %dil,%dil` + `js` (0x61bd524 / 0x61bd527) branches on bit 7 of the byte, so
   any byte >= 0x80 continues the varint.
3. **The shift guard allows at most four continuation bytes.** Every
   continuation byte advances the shift by 7 (`add $0x7,%ecx`), and a shift
   above 28 is rejected (`cmp $0x1c,%ecx` + `ja`, 0x61bd513 / 0x61bd516) - so a
   fifth continuation byte returns nullptr and 5 bytes is the longest varint
   this routine accepts.
4. **The value is assembled and stored as a 32-bit word.** The accumulator
   (`or %edi,%r8d`), the final shift (`shl %cl,%edi`) and the store
   (`mov %edi,(%rdx)`) are all 32-bit, so a 5-byte varint whose last byte has
   bits above 0x0f silently loses everything from bit 32 up - `80 80 80 80 20`
   decodes to 0 and `80 80 80 80 7f` to 0xf0000000. The encoder never emits such
   a byte (its fifth byte is `v >> 28`), so the asymmetry only shows on
   hand-built or corrupt input.

Unlike its sibling encoder at 0x61bd410 this routine is **not** read-free: its
only memory accesses are one byte load per input byte and a single 32-bit store
through `value`. It is a leaf (no calls, no relocations) and the whole body is
one `.eh_frame` FDE.

Return value: the pointer just past the last byte read, or nullptr (rax = 0).

Callers (149 direct sites, see `callers.tsv`): 27 test the returned pointer
first, so the nullptr contract is observable at the call site; 95 copy it into
another register, 19 store it, 3 use it in arithmetic, and 5 discard it (4 dead,
1 overwritten).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-get-varint32-ptr-fallback-61bd4f0-115")

START = 0x61BD4F0
END = 0x61BD53B
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
CONT = 0x80              # test %dil,%dil / js at 0x61bd524/0x61bd527
SHIFT_STEP = 7           # add $0x7,%ecx          at 0x61bd50d
MAX_SHIFT = 0x1C         # cmp $0x1c,%ecx / ja    at 0x61bd513/0x61bd516
MAX_BYTES = 5            # 4 continuation bytes + the final one

def varint_len(value):
    """The number of bytes the routine writes: 1..5, by inclusive bounds."""
    value &= M32
    if value <= BOUND1:
        return 1
    if value <= BOUND2:
        return 2
    if value <= BOUND3:
        return 3
    if value <= BOUND4:
        return 4
    return 5


def encode_varint32(value):
    """The bytes the routine writes, in order (LEB128)."""
    value &= M32
    out = []
    while value > BOUND1:
        out.append((value & BOUND1) | 0x80)
        value >>= 7
    out.append(value)
    return out


def uses_single_32bit_store(value):
    """True for the class whose write is one 32-bit store (0x61bd4a0)."""
    return varint_len(value) == STORE32_CLASS


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
    an address and bytes but no mnemonic; those are folded into the instruction
    they belong to. Memoized: the sweep calls this once.
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


# --- a small machine model for exactly the instructions this routine uses ---

_WIDTH = {"rax": 64, "eax": 32, "ax": 16, "al": 8,
          "rdx": 64, "edx": 32, "dx": 16, "dl": 8,
          "rcx": 64, "ecx": 32, "cx": 16, "cl": 8,
          "rdi": 64, "edi": 32, "di": 16, "dil": 8,
          "rsi": 64, "esi": 32, "si": 16, "sil": 8,
          "r8": 64, "r8d": 32, "r8b": 8, "r9": 64, "r9d": 32, "r9b": 8}
_CANON = {"eax": "rax", "ax": "rax", "al": "rax",
          "edx": "rdx", "dx": "rdx", "dl": "rdx",
          "ecx": "rcx", "cx": "rcx", "cl": "rcx",
          "edi": "rdi", "di": "rdi", "dil": "rdi",
          "esi": "rsi", "si": "rsi", "sil": "rsi",
          "r8d": "r8", "r8b": "r8", "r9d": "r9", "r9b": "r9"}
_IMM = re.compile(r"^\$(-?0x[0-9a-f]+|-?\d+)$")
_MEM = re.compile(r"^(?:(-?0x[0-9a-f]+|-?\d+))?\((%[a-z0-9]+)"
                  r"(?:,(%[a-z0-9]+),(\d+))?\)$")
_XMM = re.compile(r"^%xmm(\d+)$")
_16B = ("movdqu", "movdqa", "movups", "movaps")


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

    def __init__(self, buffer, dest, source, length):
        self.mem = {i: b for i, b in enumerate(buffer)}
        self.regs = {"rax": 0, "rdx": 0, "rcx": 0, "rdi": dest, "rsi": source,
                     "r8": 0, "r9": 0, "xmm0": 0, "xmm1": 0}

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
        self.regs[name] = value & ((1 << _width(text)) - 1)




def _execute(m, path=None):
    """Run the routine's decoded bytes until it returns; hand back the
    machine. Raises AssertionError on any instruction this model does not
    implement, so a silently wrong model cannot pass the differential.
    """
    insns = instruction_stream(path)
    by_addr = {i.addr: k for k, i in enumerate(insns)}
    pc = 0
    flags = {}
    steps = 0
    while True:
        steps += 1
        assert steps <= 5000, "no termination"
        assert pc < len(insns), "ran off the end of the routine"
        ins = insns[pc]
        mn = ins.mnemonic
        ops = split_ops(ins.op_str)
        pc += 1
        if mn in ("endbr64", "nop", "nopl", "nopw", "int3"):
            continue
        if mn in ("test", "cmp"):
            # the operand width matters here: the routine tests one byte
            # (`test %dil,%dil`) and compares 32- and 64-bit values.
            w = _width(ops[1] if _IMM.match(ops[0]) else ops[0])
            mask = (1 << w) - 1
            a = _IMM.match(ops[0])
            a = int(a.group(1), 0) & mask if a else m.get(ops[0]) & mask
            b = m.get(ops[1]) & mask
            if mn == "test":                 # AND: ZF set when (a & b) == 0
                r, flags["cf"] = a & b, False
            else:                            # CMP a,b computes b - a
                r, flags["cf"] = (b - a) & mask, b < a
            flags["zf"] = r == 0
            flags["sf"] = (r >> (w - 1)) & 1
            continue
        if mn == "jmp":
            target = int(ops[0].split()[0], 16)
            assert target in by_addr, (ins, "target outside the routine")
            pc = by_addr[target]
            continue
        if mn in ("je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "js"):
            zf, cf, sf = flags.get("zf"), flags.get("cf"), flags.get("sf")
            take = {"je": zf, "jz": zf, "jne": not zf, "jnz": not zf,
                    "ja": (not zf) and (not cf), "jae": not cf,
                    "jb": cf, "jbe": cf or zf, "js": sf}[mn]
            if take:
                target = int(ops[0].split()[0], 16)
                assert target in by_addr, (ins, "target outside the routine")
                pc = by_addr[target]
            continue
        if mn in ("jl", "jle", "jg", "jge"):
            raise AssertionError(f"signed branch {mn} is not part of this routine")
        if mn in _16B:
            src, dst = ops
            if _MEM.match(src) and _MEM.match(dst):
                raise AssertionError(f"mem-to-mem move: {ins}")
            if _MEM.match(src):
                m.set(dst, m.load(m.addr_of(src), 16))
            elif _MEM.match(dst):
                m.store(m.addr_of(dst), m.get(src), 16)
            else:
                m.set(dst, m.get(src))
            continue
        if mn == "mov":
            src, dst = ops
            imm = _IMM.match(src)
            if _MEM.match(dst):                      # a store
                size = _width(src) // 8
                value_ = (int(imm.group(1), 0) if imm else m.get(src))
                m.store(m.addr_of(dst), value_, size)
                continue
            if imm:
                m.set(dst, int(imm.group(1), 0))
            elif _MEM.match(src):
                m.set(dst, m.load(m.addr_of(src), _width(dst) // 8))
            else:
                m.set(dst, m.get(src))
            continue
        if mn == "lea":
            src, dst = ops
            m.set(dst, m.addr_of(src))
            continue
        if mn in ("movzbl", "movzwl", "movsbl", "movslq"):
            src, dst = ops
            size = {"movzbl": 1, "movzwl": 2, "movsbl": 1, "movslq": 4}[mn]
            if _MEM.match(src):
                val = m.load(m.addr_of(src), size)
            else:                        # register source: take the low `size`
                val = m.get(src) & ((1 << (8 * size)) - 1)
            if mn in ("movsbl", "movslq") and val >= (1 << (8 * size - 1)):
                val -= (1 << (8 * size))
            m.set(dst, val & M64)
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
            else:
                out = cur >> (s & 63)
            m.set(dst, out & M64)
            continue
        if mn == "ret":
            return m
        raise AssertionError(f"unimplemented instruction: {ins}")


# --- the model -------------------------------------------------------------

def _out_slot(data):
    return len(data)                      # where `mov %edi,(%rdx)` stores


def _load_u32(mem, at):
    return sum(mem.get(at + i, 0) << (8 * i) for i in range(4))


def get_varint32(data, limit=None, start=0):
    """The contract in Python: decode one LEB128 uint32 out of `data`.

    `limit` is the caller's one-past-the-end bound (default: len(data)).
    Returns `(value, next_index)`, or None where the routine returns nullptr:
    when `start >= limit`, when the varint runs past the limit, or when the
    shift would exceed 28 (a fifth continuation byte).
    """
    data = bytes(data)
    limit = len(data) if limit is None else limit
    if start >= limit:
        return None
    i, shift, acc = start, 0, 0
    while True:
        b = data[i]
        i += 1
        if b & CONT:
            acc = (acc | (((b & 0x7F) << shift) & M32)) & M32
            shift += SHIFT_STEP
            if shift > MAX_SHIFT or i >= limit:
                return None
            continue
        return ((b << shift) | acc) & M32, i


def get_varint32_decoded(data, limit=None, start=0, path=None):
    """Same contract, by executing the routine's own decoded bytes."""
    data = bytes(data)
    limit = len(data) if limit is None else limit
    m = Machine(list(data), start, limit, limit)
    m.regs["rdx"] = _out_slot(data)       # where `mov %edi,(%rdx)` writes
    m = _execute(m, path)
    if m.get("rax") == 0:
        return None
    return _load_u32(m.mem, _out_slot(data)), m.get("rax")


def decoded_writes(data, limit=None, start=0, path=None):
    """The addresses the decoded run wrote, anywhere outside the input.

    States the store claim positively: a successful decode writes exactly one
    32-bit word through `value`, and a failed decode writes nothing at all.
    """
    data = bytes(data)
    limit = len(data) if limit is None else limit
    m = Machine(list(data), start, limit, limit)
    m.regs["rdx"] = _out_slot(data)
    m = _execute(m, path)
    return {a for a in m.mem if a >= _out_slot(data)}


def accepts_a_fifth_continuation_byte():
    """False: the shift guard rejects a fifth continuation byte."""
    return get_varint32(bytes([0x80] * 5), 5) is not None


# --- cases, ledger and evidence tables -------------------------------------

_LETTERS = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5}
FAMILIES = ("one", "two", "three", "four", "five", "fail")

# The four rows kept verbatim at the head of each family. The value column is
# the model's answer and is checked against the decoded execution.
BOUNDARY_CASES = {
    "one": [([0x00], 1), ([0x7F], 1), ([0x01, 0xAA], 2), ([0x01, 0xAA], 1)],
    "two": [([0x80, 0x01], 2), ([0xFF, 0x7F], 2), ([0x80, 0x7F], 2),
            ([0x80, 0x00], 2)],
    "three": [([0x80, 0x80, 0x01], 3), ([0xFF, 0xFF, 0x7F], 3),
              ([0x80, 0x80, 0x7F], 3), ([0x81, 0x80, 0x00], 3)],
    "four": [([0x80, 0x80, 0x80, 0x01], 4), ([0xFF, 0xFF, 0xFF, 0x7F], 4),
             ([0x80, 0x80, 0x80, 0x7F], 4), ([0x81, 0x80, 0x80, 0x00], 4)],
    "five": [([0x80, 0x80, 0x80, 0x80, 0x01], 5),
             ([0xFF, 0xFF, 0xFF, 0xFF, 0x0F], 5),
             ([0x80, 0x80, 0x80, 0x80, 0x20], 5),
             ([0x80, 0x80, 0x80, 0x80, 0x7F], 5)],
    "fail": [([], 0), ([0x01], 0), ([0x80], 1), ([0x80, 0x80], 2),
             ([0x80] * 5, 5)],
}


def _varint_bytes(rng, n, wide_top=False):
    """A well-formed n-byte varint: n-1 bytes with bit 7 set, then a final byte
    without it."""
    out = [rng.randrange(0x80, 0x100) for _ in range(n - 1)]
    top = rng.randrange(0, 0x80)
    if wide_top and n == 5 and rng.random() < 0.4:
        top = rng.randrange(0x10, 0x80)    # bits above 32: silently dropped
    out.append(top)
    return out


def _fail_case(rng):
    """A buffer on which the routine returns nullptr, plus the limit."""
    kind = rng.randrange(4)
    if kind == 0:                          # p >= limit
        n = rng.randrange(0, 6)
        return [rng.randrange(0, 0x100) for _ in range(n)], 0
    if kind == 1 and rng.random() < 0.5:   # an empty buffer
        return [], 0
    n = rng.randrange(1, 6)
    if kind == 2:                          # truncated at the limit
        bs = [rng.randrange(0x80, 0x100) for _ in range(n)]
        return bs[:rng.randrange(1, n + 1)], 0
    if kind == 3:                          # a fifth continuation byte
        bs = [rng.randrange(0x80, 0x100) for _ in range(5)]
        tail = [rng.randrange(0, 0x100) for _ in range(rng.randrange(0, 3))]
        return bs + tail, len(bs + tail)
    bs = [rng.randrange(0x80, 0x100)]      # a varint with no termination
    return bs, 0


def generate_cases(seed=115):
    """The full sweep: 2400 cases, 400 per family, the boundaries first."""
    import random
    rng = random.Random(seed)
    out = []
    for name in ("one", "two", "three", "four", "five"):
        n = _LETTERS[name]
        rows = [{"bytes": bs, "limit": lim} for bs, lim in BOUNDARY_CASES[name]]
        while len(rows) < 400:
            bs = _varint_bytes(rng, n, wide_top=(n == 5))
            tail = [rng.randrange(0, 0x100)
                    for _ in range(rng.randrange(0, 4))]
            buf = bs + tail
            lim = len(buf)
            if rng.random() < 0.25:        # a limit inside the tail
                lim = n + rng.randrange(0, len(tail) + 1)
            rows.append({"bytes": buf, "limit": lim})
        assert len(rows) == 400, (name, len(rows))
        out.extend({"family": name, **r} for r in rows)
    rows = [{"bytes": bs, "limit": lim} for bs, lim in BOUNDARY_CASES["fail"]]
    while len(rows) < 400:
        bs, lim = _fail_case(rng)
        rows.append({"bytes": bs, "limit": lim})
    out.extend({"family": "fail", **r} for r in rows)
    assert len(out) == 2400, len(out)
    return out


LEDGER_PER_FAMILY = 50


def _stride(seq, need):
    assert need <= len(seq), (need, len(seq))
    if need == len(seq):
        return list(seq)
    step = len(seq) / need
    return [seq[int(i * step)] for i in range(need)]


def _answer(case):
    """The model's (value, next) for a case, or None."""
    return get_varint32(case["bytes"], case["limit"])


def ledger_rows(rows=None):
    """A 300-case stratified, reviewable subset: the boundary rows of every
    family are kept verbatim and the rest of each family is strided."""
    rows = list(rows) if rows is not None else generate_cases()
    fams = {}
    for r in rows:
        fams.setdefault(r["family"], []).append(r)
    out = []
    for name in FAMILIES:
        bunch = fams[name]
        head = bunch[:len(BOUNDARY_CASES[name])]
        out.extend(head + _stride(bunch[len(head):],
                                  LEDGER_PER_FAMILY - len(head)))
    assert len(out) == 300, len(out)
    for i, r in enumerate(out):
        r = dict(r)
        r["id"] = i + 1
        ans = _answer(r)
        r["result"] = "ok" if ans else "null"
        r["value"] = ans[0] if ans else None
        r["next"] = ans[1] if ans else None
        out[i] = r
    return out


def replay_case(case):
    """Re-derive a committed row: model and decoded execution must agree."""
    ans = _answer(case)
    got = get_varint32_decoded(case["bytes"], case["limit"])
    assert ans == got, (case, ans, got)
    return ans


def _bytes(values):
    return "".join(f"{b:02x}" for b in values)


def cases_tsv_rows():
    rows = ["id\tfamily\tbytes\tlimit\tresult\tvalue\tnext"]
    for r in ledger_rows():
        rows.append("\t".join([
            str(r["id"]), r["family"], _bytes(r["bytes"]), str(r["limit"]),
            r["result"], "-" if r["value"] is None else hex(r["value"]),
            "-" if r["next"] is None else str(r["next"]),
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
