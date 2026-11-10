"""Model of node #115 libz `_tr_flush_bits` 0x630b9c0..0x630ba48.

`void _tr_flush_bits(deflate_state *s)` - zlib's pending-bit flush, the
`bi_flush` step of `deflate_trees.c`: emit the whole bytes still sitting in the
bit buffer and keep the sub-byte remainder.

Behaviour read off the routine's own committed instruction bytes (`main.txt`,
hashed against the digest-verified artifact by `verify.py`):

  630b9c0  endbr64
  630b9c4  mov 0x1734(%rdi),%eax     eax = s->bi_valid            (u32 at +0x1734)
  630b9ca  cmp $0x10,%eax
  630b9cd  je  0x630ba00             bi_valid == 16 -> emit TWO bytes
  630b9cf  cmp $0x7,%eax
  630b9d2  jle 0x630b9fd             bi_valid <= 7 (SIGNED) -> emit nothing
  630b9d4  mov 0x28(%rdi),%rax       rax = s->pending              (u64 at +0x28)
  630b9d8  movzwl 0x1730(%rdi),%ecx  ecx = s->bi_buf               (u16 at +0x1730)
  630b9df  mov 0x10(%rdi),%rdx       rdx = s->pending_out          (ptr at +0x10)
  630b9e3  lea 0x1(%rax),%rsi / mov %rsi,0x28(%rdi)   s->pending = pending + 1
  630b9eb  mov %cl,(%rdx,%rax,1)     pending_out[pending] = (Byte)bi_buf
  630b9ee  subl $0x8,0x1734(%rdi)    s->bi_valid -= 8              (4-byte RMW)
  630b9f5  shrw $0x8,0x1730(%rdi)    s->bi_buf >>= 8               (2-byte RMW)
  630b9fd  ret                       (leaves rax = bi_valid)
  630ba00  ... the 16-bit path: the same byte store, then the HIGH byte
  630ba1e  movzbl 0x1731(%rdi),%ecx  ecx = the second byte of bi_buf
  630ba34  xor %eax,%eax
  630ba36  mov %ax,0x1730(%rdi)      s->bi_buf = 0                 (2-byte store)
  630ba3d  movl $0x0,0x1734(%rdi)    s->bi_valid = 0               (4-byte store)
  630ba47  ret                       (leaves rax = 0)

Seven build-specific details follow from those bytes and are exercised by the
ledger:

1. **The dispatch is three-way and its order matters.** `bi_valid == 16` is
   tested first (a two-byte emit), then `bi_valid <= 7` (nothing to do); every
   other value falls into the *one-byte* path. In particular a value of 17, 24
   or 100 emits one byte and subtracts 8 (17 -> 9, 24 -> 16, 100 -> 92), which is
   outside zlib's own invariant `bi_valid <= 16` but is what the bytes do.
2. **The `<= 7` test is SIGNED.** `cmp $0x7,%eax` + `jle` treats `bi_valid` as a
   signed 32-bit value, so any value with bit 31 set (0x80000000 .. 0xffffffff)
   is "negative", satisfies `<= 7`, and emits **nothing** - even though the field
   is an unsigned count. An unsigned `jbe` model differs on exactly those values,
   which the ledger keeps verbatim.
3. **The counter is incremented before the byte is stored.** `lea 0x1(%rax),%rsi`
   + `mov %rsi,0x28(%rdi)` commit `pending + 1` first, and the store then uses the
   pre-increment index (`mov %cl,(%rdx,%rax,1)`), so the byte lands at
   `pending_out[old_pending]`, not one past it.
4. **The two-byte emit is little-endian and in ascending address order.** The low
   byte comes from `movzwl` + `%cl` (0x630ba04..0x630ba17) and the high byte from
   `movzbl 0x1731(%rdi)` (the second byte of `bi_buf`) stored in the next slot,
   so `pending_out[p]` gets `bi_buf & 0xff` and `pending_out[p+1]` gets
   `bi_buf >> 8`.
5. **The 8..15 path shifts the bit buffer in place, as a 2-byte RMW.** `shrw
   $0x8,0x1730(%rdi)` moves the high byte down, and `subl $0x8,0x1734(%rdi)`
   decrements the count by exactly the eight bits it just emitted.
6. **The 16-bit path zeroes both fields, with stores of the fields' own widths.**
   `mov %ax,0x1730(%rdi)` writes 2 bytes of zero and `movl $0x0,0x1734(%rdi)`
   writes 4 - the counts are not merged or masked, they are overwritten.
7. **The return register is not a return value.** rax is left as `bi_valid` on
   the nothing-to-do path, as the *old* `pending` on the one-byte path, and as 0
   on the two-byte path - three different leftovers on three paths. Consistently,
   the census finds that **all 26 call sites overwrite rax before reading it**.

There is **no bounds check**: nothing compares `pending` with `pending_buf_size`
(`+0x20`) before the stores, and nothing compares the pointer with any limit.
Struct offsets pinned by the accesses: `pending_out` `+0x10` (pointer),
`pending` `+0x28` (u64), `bi_buf` `+0x1730` (u16), `bi_valid` `+0x1734` (u32).
The window is a leaf: no calls, no relocations, one `.eh_frame` FDE.

Version note carried from the vendor census: the release is **not** pinned by
this window - these bodies are identical in the zlib 1.3.2 bundled by libz-sys
1.1.31, so the window fixes behaviour but not a zlib revision.
"""

from __future__ import annotations

import re
import sys

import capstone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-libz-tr-flush-bits-630b9c0-115")

START = 0x630B9C0
END = 0x630BA48
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1
BIT_SHIFT = 3            # shr $0x3,%ecx   at 0x628f71c
BIT_MASK = 7             # and $0x7,%edx   at 0x628f719
CONTAINER_BYTES = 8      # mov (%rax),%rax - one 8-byte load at 0x628f729
STATUS_UNFINISHED = 0    # xor %eax,%eax    at 0x628f72f
STRUCT_CONTAINER = 0x00  # mov %rax,(%rdi)      at 0x628f72c
STRUCT_BITS = 0x08       # mov %edx,0x8(%rdi)   at 0x628f71f
STRUCT_PTR = 0x10        # mov %rax,0x10(%rdi)  at 0x628f725
PTR_BASE = 0x40000000   # the modelled bitD->ptr for every case

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



_MD = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
_MD.detail = True
_MEM_SIZE_CACHE = {}


def mem_size(ins):
    """The access width, in bytes, of `ins`'s memory operand (None if it has
    none). objdump's text drops this: `subl $x,0x1734(%rdi)` is a 4-byte RMW
    while `shrw $x,0x1730(%rdi)` is a 2-byte one and `mov %ax,0x1730(%rdi)`
    stores 2 bytes - none of which is visible in the operand text alone."""
    if ins.addr in _MEM_SIZE_CACHE:
        return _MEM_SIZE_CACHE[ins.addr]
    out = None
    for dec in _MD.disasm(ins.raw, ins.addr):
        for op in dec.operands:
            if op.type == capstone.x86.X86_OP_MEM:
                out = op.size
                break
        break
    _MEM_SIZE_CACHE[ins.addr] = out
    return out


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


_HANDLED = ("mov", "lea", "movzbl", "movzwl", "movsbl", "movslq", "add",
            "sub", "and", "or", "xor", "shl", "shr", "sar", "cmp", "test",
            "jmp", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "js",
            "jl", "jle", "jg", "jge", "ret", "endbr64", "nop", "nopl", "nopw",
            "int3") + _16B


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
        # objdump writes AT&T size suffixes on memory operands (`subl`, `shrw`,
        # `movl`) that Capstone folds into the operand width; normalise them so
        # the dispatch below can match on the bare mnemonic.
        if mn not in _HANDLED and mn[:-1] in _HANDLED:
            mn = mn[:-1]
        ops = split_ops(ins.op_str)
        pc += 1
        if mn in ("endbr64", "nop", "nopl", "nopw", "int3"):
            continue
        if mn == "xchg":                 # `xchg %ax,%ax` is a 2-byte padding nop
            a, b = split_ops(ins.op_str) if "," in ins.op_str else (None, None)
            assert a is not None and a == b, f"real xchg is not modelled: {ins}"
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
            # signed overflow, needed by the jl/jle/jg/jge family: for a
            # subtraction r = b - a it is set exactly when the operands'
            # signs differ AND the result's sign differs from b's.
            flags["of"] = 0 if mn == "test" else \
                (((b ^ a) & (b ^ r)) >> (w - 1)) & 1
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
            zf, sf, of = flags.get("zf"), flags.get("sf"), flags.get("of")
            lt = sf != of                    # signed "less than"
            take = {"jl": lt, "jle": lt or zf, "jg": (not lt) and (not zf),
                    "jge": not lt}[mn]
            if take:
                target = int(ops[0].split()[0], 16)
                assert target in by_addr, (ins, "target outside the routine")
                pc = by_addr[target]
            continue
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
                size = mem_size(ins) or (_width(src) // 8)
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
            msize = mem_size(ins)
            if _MEM.match(src):
                s = m.load(m.addr_of(src), msize or (_width(dst) // 8))
            elif imm:
                s = int(imm.group(1), 0) & M64
            else:
                s = m.get(src)
            if _MEM.match(dst):                      # a memory RMW
                size = msize or 8
                cur = m.load(m.addr_of(dst), size)
                smask = (1 << (8 * size)) - 1
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
                m.store(m.addr_of(dst), out & smask, size)
                continue
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

STRUCT = 0x1000          # the modelled deflate_state
BUFFER = 0x8000          # the modelled pending_out buffer
OFF_PTR = 0x10           # pending_out
OFF_PENDING = 0x28       # pending (u64)
OFF_BIBUF = 0x1730       # bi_buf (u16)
OFF_BIVALID = 0x1734     # bi_valid (u32)


def _rm(m, addr, size):
    return sum(m.mem.get(addr + i, 0) << (8 * i) for i in range(size))


def _wm(m, addr, value, size):
    for i in range(size):
        m.mem[(addr + i) & M64] = (value >> (8 * i)) & 0xFF


def _as_signed32(value):
    value &= M32
    return value - (1 << 32) if value & 0x80000000 else value


def flush_bits(bi_valid, bi_buf, pending):
    """The routine's effect, in Python.

    Returns `(bi_valid, bi_buf, pending, emitted, leftover)`: the emitted bytes
    (little-endian, ascending), the new field values, and the value the return
    register is left holding - which is a leftover, not a status.
    """
    bi_valid &= M32
    bi_buf &= 0xFFFF
    if bi_valid == 0x10:
        return (0, 0, pending + 2, [bi_buf & 0xFF, (bi_buf >> 8) & 0xFF], 0)
    if _as_signed32(bi_valid) <= 7:          # SIGNED, like the jle at 0x630b9d2
        return (bi_valid, bi_buf, pending, [], bi_valid)
    return ((bi_valid - 8) & M32, (bi_buf >> 8) & 0xFFFF, pending + 1,
            [bi_buf & 0xFF], pending)


def flush_bits_decoded(bi_valid, bi_buf, pending, path=None):
    """Same effect, by executing the routine's own decoded bytes."""
    m = Machine([], 0, 0, 0)
    m.regs["rdi"] = STRUCT
    _wm(m, STRUCT + OFF_PTR, BUFFER, 8)
    _wm(m, STRUCT + OFF_PENDING, pending, 8)
    _wm(m, STRUCT + OFF_BIBUF, bi_buf & 0xFFFF, 2)
    _wm(m, STRUCT + OFF_BIVALID, bi_valid & M32, 4)
    m = _execute(m, path)
    new_pending = _rm(m, STRUCT + OFF_PENDING, 8)
    emitted = [_rm(m, BUFFER + i, 1) for i in range(pending, new_pending)]
    return (_rm(m, STRUCT + OFF_BIVALID, 4), _rm(m, STRUCT + OFF_BIBUF, 2),
            new_pending, emitted, m.get("rax"))


def flush_accesses(bi_valid, bi_buf, pending, path=None):
    """The (address, size) of every load and store the decoded run performs.

    Used to state the emit claim positively: the byte stores go to the pending
    buffer with ascending addresses, and the field writes use each field's own
    width.
    """
    m = Machine([], 0, 0, 0)
    m.regs["rdi"] = STRUCT
    _wm(m, STRUCT + OFF_PTR, BUFFER, 8)
    _wm(m, STRUCT + OFF_PENDING, pending, 8)
    _wm(m, STRUCT + OFF_BIBUF, bi_buf & 0xFFFF, 2)
    _wm(m, STRUCT + OFF_BIVALID, bi_valid & M32, 4)
    loads, stores = [], []
    real_load, real_store = m.load, m.store
    m.load = lambda a, size: (loads.append((a, size)), real_load(a, size))[1]
    m.store = lambda a, v, size: (stores.append((a, size)),
                                  real_store(a, v, size))[1]
    _execute(m, path)
    return loads, stores


# --- cases, ledger and evidence tables -------------------------------------

FAMILIES = ("lower", "upper", "anomalous", "negative", "sixteen")

# The four rows kept verbatim at the head of each family: (bi_valid, bi_buf,
# pending). "sixteen" holds bi_valid fixed so the two-byte emit varies instead.
BOUNDARY_CASES = {
    "lower": [(0, 0x1234, 0), (1, 0xABCD, 1), (6, 0xFFFF, 2), (7, 0x0000, 3)],
    "upper": [(8, 0x1234, 0), (9, 0xABCD, 1), (0xE, 0xFFFF, 2),
              (0xF, 0x0001, 3)],
    "anomalous": [(0x11, 0x1234, 0), (0x12, 0xABCD, 1), (0x17, 0xFFFF, 2),
                  (0x18, 0x0000, 3)],
    "negative": [(0x80000000, 0x1234, 0), (0x80000001, 0xABCD, 1),
                 (0xFFFFFFFE, 0xFFFF, 2), (0xFFFFFFFF, 0x0000, 3)],
    "sixteen": [(0x10, 0x1234, 0), (0x10, 0x0000, 1), (0x10, 0x00FF, 2),
                (0x10, 0xFF00, 3)],
}


def _draw(rng, name):
    if name == "lower":
        return rng.randrange(0, 8)
    if name == "upper":
        return rng.randrange(8, 16)
    if name == "anomalous":
        return rng.choice([rng.randrange(17, 0x1000),
                           rng.randrange(0x1000, 0x80000000)])
    if name == "negative":
        return rng.randrange(0x80000000, 0x100000000)
    return 0x10


def generate_cases(seed=115):
    """The full sweep: 2400 cases, 480 per family, the boundaries first."""
    import random
    rng = random.Random(seed)
    out = []
    for name in FAMILIES:
        rows = [{"bi_valid": v, "bi_buf": b, "pending": p}
                for v, b, p in BOUNDARY_CASES[name]]
        while len(rows) < 480:
            rows.append({"bi_valid": _draw(rng, name),
                         "bi_buf": rng.getrandbits(16),
                         "pending": rng.randrange(0, 8)})
        assert len(rows) == 480, (name, len(rows))
        out.extend({"family": name, **r} for r in rows)
    assert len(out) == 2400, len(out)
    return out


LEDGER_PER_FAMILY = 60


def _stride(seq, need):
    assert need <= len(seq), (need, len(seq))
    if need == len(seq):
        return list(seq)
    step = len(seq) / need
    return [seq[int(i * step)] for i in range(need)]


def _answer(case):
    return flush_bits(case["bi_valid"], case["bi_buf"], case["pending"])


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
        new_valid, new_buf, new_pending, emitted, leftover = _answer(r)
        r["new_bi_valid"] = new_valid
        r["new_bi_buf"] = new_buf
        r["new_pending"] = new_pending
        r["emitted"] = emitted
        r["leftover"] = leftover
        out[i] = r
    return out


def replay_case(case):
    """Re-derive a committed row: model and decoded execution must agree."""
    ans = _answer(case)
    got = flush_bits_decoded(case["bi_valid"], case["bi_buf"], case["pending"])
    assert ans == got, (case, ans, got)
    return ans


def _bytes(values):
    return "".join(f"{b:02x}" for b in values)


def cases_tsv_rows():
    rows = ["id\tfamily\tbi_valid\tbi_buf\tpending\temitted\tnew_bi_valid"
            "\tnew_bi_buf\tnew_pending\trax_leftover"]
    for r in ledger_rows():
        rows.append("\t".join([
            str(r["id"]), r["family"], hex(r["bi_valid"]), hex(r["bi_buf"]),
            str(r["pending"]), _bytes(r["emitted"]) or "-",
            hex(r["new_bi_valid"]), hex(r["new_bi_buf"]),
            str(r["new_pending"]), hex(r["leftover"]),
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
