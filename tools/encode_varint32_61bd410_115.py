"""Model of node #115 rocksdb `EncodeVarint32` 0x61bd410..0x61bd4e9 (217 bytes).

`char* EncodeVarint32(char* dst, uint32_t v)` — the LEB128 encoder from
rocksdb's `util/coding.cc`:

  writes 1..5 bytes to `dst` and returns the position just past the last one

Behaviour read off the routine's own committed instruction bytes (`main.txt`,
hashed against the digest-verified artifact by `verify.py`):

  v <= 0x7f           -> 1 byte    mov %sil,(%rdi)            0x61bd41c
  v <= 0x3fff         -> 2 bytes   two byte stores           0x61bd448/44b
  v <= 0x1fffff       -> 3 bytes   three byte stores         0x61bd4b4..4ba
  v <= 0x0fffffff     -> 4 bytes   ONE 32-bit store          0x61bd4a0
  otherwise           -> 5 bytes   five byte stores          0x61bd4ce..4e0

Every class computes rdx = dst + n and returns it through a
`mov %rdx,%rax / ret` pair. There are three such tail sites - 0x61bd423,
0x61bd44e and 0x61bd4be - and the 4- and 5-byte classes jump to the first
(0x61bd4a2, 0x61bd4e4) while the 1-byte class falls into it; the 2- and
3-byte classes have their own identical copies.

Four build-specific details follow from those bytes and are exercised by the
ledger:

1. **The 4-byte class writes with a single 32-bit store.** The bytes are
   composed in a register (`movzbl`/`shl $8`/`or` at 0x61bd47c..0x61bd49d) and
   written by one `mov %ecx,(%rax)` at 0x61bd4a0, whereas the 1/2/3/5-byte
   classes write one byte per store. The store is unaligned, so it is the only
   class whose write is a single 4-byte memory access.
2. **The class bounds are inclusive and checked with `ja`.** Each test is
   `cmp $bound,%esi` followed by a jump on *unsigned above*, so `v == bound`
   stays in the smaller class: 0x7f is 1 byte, 0x3fff is 2, 0x1fffff is 3 and
   0x0fffffff is 4.
3. **The continuation bit is an `or $0xffffff80`, and the final byte is stored
   unmasked.** The last byte of each multi-byte class is written with a plain
   byte move (e.g. `mov %cl,0x1(%rdi)`), which is safe only because the class
   bound guarantees the remaining bits are <= 0x7f.
4. **The top byte of the 5-byte class is `v >> 28`** (`shr $0x1c,%esi` at
   0x61bd4cb), so only its low nibble can be non-zero for a `uint32_t`.

The routine is a leaf: no calls, no relocations, and it reads no memory — the
only memory accesses are the stores. The whole body is one `.eh_frame` FDE.

Return value: `dst + n` (the end pointer), never a count.

Callers (165 direct sites, see `callers.tsv`): 139 of them use the returned
pointer in arithmetic — the recorded continuation is
`mov rdx,rax; sub rax,<base>` — i.e. they recover the encoded length by
subtracting the buffer's base pointer from the returned end pointer. 24 copy it
into another register and 2 store it. No site discards it.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-encode-varint32-61bd410-115")

START = 0x61BD410
END = 0x61BD4E9
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
BOUND1 = 0x7F            # cmp $0x7f,%esi   at 0x61bd417
BOUND2 = 0x3FFF          # cmp $0x3fff,%esi at 0x61bd43c
BOUND3 = 0x1FFFFF        # cmp $0x1fffff,%esi at 0x61bd460
BOUND4 = 0x0FFFFFFF      # cmp $0xfffffff,%esi at 0x61bd474
STORE32_CLASS = 4        # the class that uses one 32-bit store, not byte stores


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


def encode_varint32_decoded(value, path=None):
    """Execute the routine's own decoded bytes against an empty buffer.

    Returns the bytes it wrote, so the result can be compared with
    `encode_varint32`. Raises AssertionError on any instruction this model does
    not implement.
    """
    insns = instruction_stream(path)
    by_addr = {i.addr: k for k, i in enumerate(insns)}
    m = Machine([], 0, 0, 0)
    # seed the CANONICAL 64-bit names: the accessors canonicalise sub-registers
    # (%esi -> rsi), so seeding "esi" directly would never be read.
    m.regs["rdi"] = 0                        # dst
    m.regs["rsi"] = value & M32              # uint32_t v
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
            a = _IMM.match(ops[0])
            a = int(a.group(1), 0) & M64 if a else m.get(ops[0])
            b = m.get(ops[1])
            if mn == "test":                 # AND: ZF set when (a & b) == 0
                flags["zf"] = (a & b) == 0
                flags["cf"] = False
            else:                            # CMP a,b computes b - a
                flags["zf"] = ((b - a) & M64) == 0
                flags["cf"] = (b & M64) < (a & M64)
            continue
        if mn == "jmp":
            target = int(ops[0].split()[0], 16)
            assert target in by_addr, (ins, "target outside the routine")
            pc = by_addr[target]
            continue
        if mn in ("je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe"):
            zf, cf = flags.get("zf"), flags.get("cf")
            take = {"je": zf, "jz": zf, "jne": not zf, "jnz": not zf,
                    "ja": (not zf) and (not cf), "jae": not cf,
                    "jb": cf, "jbe": cf or zf}[mn]
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
            return [m.load(i, 1) for i in range(m.get("rax"))]
        raise AssertionError(f"unimplemented instruction: {ins}")


# --- cases, ledger and evidence tables -------------------------------------

def _fill(rng, count, lo, hi):
    return [rng.randrange(lo, hi + 1) for _ in range(count)]


def generate_cases(seed=115):
    """The full sweep: 2400 cases, 480 per length class, boundaries first."""
    import random
    rng = random.Random(seed)
    fams = {
        "one":   [0, 1, BOUND1] + _fill(rng, 477, 0, BOUND1),
        "two":   [BOUND1 + 1, BOUND2] + _fill(rng, 478, BOUND1 + 1, BOUND2),
        "three": [BOUND2 + 1, BOUND3] + _fill(rng, 478, BOUND2 + 1, BOUND3),
        "four":  [BOUND3 + 1, BOUND4] + _fill(rng, 478, BOUND3 + 1, BOUND4),
        "five":  [BOUND4 + 1, M32] + _fill(rng, 478, BOUND4 + 1, M32),
    }
    out = []
    for name in ("one", "two", "three", "four", "five"):
        rows = [{"family": name, "value": v & M32} for v in fams[name]]
        assert len(rows) == 480, (name, len(rows))
        out.extend(rows)
    return out


LEDGER_PER_FAMILY = 60


def _stride(seq, need):
    assert need <= len(seq), (need, len(seq))
    if need == len(seq):
        return list(seq)
    step = len(seq) / need
    return [seq[int(i * step)] for i in range(need)]


def ledger_rows(rows=None):
    """A 300-case stratified, reviewable subset: the class boundaries are kept
    verbatim and the rest of each class is strided."""
    rows = list(rows) if rows is not None else generate_cases()
    fams = {}
    for r in rows:
        fams.setdefault(r["family"], []).append(r)
    out = []
    for name in sorted(fams):
        bunch = fams[name]
        head = bunch[:4]                      # the boundaries, unchanged
        rest = bunch[4:]
        out.extend(head + _stride(rest, LEDGER_PER_FAMILY - len(head)))
    assert len(out) == 300, len(out)
    for i, r in enumerate(out):
        r = dict(r)
        r["id"] = i + 1
        r["bytes"] = encode_varint32(r["value"])
        r["nbytes"] = varint_len(r["value"])
        r["store32"] = uses_single_32bit_store(r["value"])
        out[i] = r
    return out


def replay_case(case):
    return encode_varint32(case["value"])


def _bytes(values):
    return "".join(f"{b:02x}" for b in values)


def cases_tsv_rows():
    rows = ["id\tfamily\tvalue\tbytes\tnbytes\tsingle_32bit_store"]
    for r in ledger_rows():
        rows.append("\t".join([
            str(r["id"]), r["family"], hex(r["value"]), _bytes(r["bytes"]),
            str(r["nbytes"]), "1" if r["store32"] else "0",
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
