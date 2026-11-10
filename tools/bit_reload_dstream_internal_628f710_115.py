"""Model of node #115 zstd `BIT_reloadDStream_internal` 0x628f710..0x628f732.

`BIT_reloadDStream_internal(BIT_DStream_t* bitD)` - zstd's bitstream
renormalisation, from `lib/decompress/huf_decompress.c` (`bitstream.h`): rewind
the byte pointer by the whole bytes already consumed, keep the sub-byte
remainder, and reload the 64-bit container from the new position.

Behaviour read off the routine's own committed instruction bytes (`main.txt`,
hashed against the digest-verified artifact by `verify.py`):

  628f710  mov 0x8(%rdi),%edx      edx = bitD->bitsConsumed        (u32 at +0x08)
  628f713  mov 0x10(%rdi),%rax     rax = bitD->ptr                 (ptr at +0x10)
  628f717  mov %edx,%ecx           ecx = bitsConsumed
  628f719  and $0x7,%edx           edx = bitsConsumed & 7      <- the new bitPos
  628f71c  shr $0x3,%ecx           ecx = bitsConsumed >> 3     <- whole bytes
  628f71f  mov %edx,0x8(%rdi)      bitD->bitsConsumed = bitPos
  628f722  sub %rcx,%rax           rax = ptr - whole bytes     <- moves BACKWARD
  628f725  mov %rax,0x10(%rdi)     bitD->ptr = rax
  628f729  mov (%rax),%rax         rax = *(u64*)rax            MEM_readLEST
  628f72c  mov %rax,(%rdi)         bitD->bitContainer = rax    (8 bytes at +0x00)
  628f72f  xor %eax,%eax           return the constant 0
  628f731  ret

Five build-specific details follow from those bytes and are exercised by the
ledger:

1. **`bitsConsumed` is split, and only the remainder survives.** The sub-byte
   part (`& 7`) is written back as the new `bitsConsumed`, so after the call it
   is always in [0,7]; the whole-byte part (`>> 3`) is consumed by the pointer
   rewind. `mov %edx,%ecx` zero-extends, so the rewind is an *unsigned* division
   by 8 of a 32-bit field.
2. **The pointer moves backwards, not forwards.** `sub %rcx,%rax` from the
   current `ptr` re-reads bytes that were already delivered: the container is an
   8-byte window that overlapped the buffer, and renormalisation slides it
   forward only as far as it has actually been consumed. A model that advanced
   the pointer would produce different containers.
3. **The reload is one unconditional 8-byte little-endian load that REPLACES the
   container.** `mov (%rax),%rax` followed by `mov %rax,(%rdi)`: no shift, no OR
   with the old bits, no byte-wise merge.
4. **The return value is the constant 0.** `xor %eax,%eax` on the only exit: the
   12-instruction body contains **no comparison and no conditional branch**, so
   it cannot distinguish zstd's other `BIT_DStream_status` values (end of buffer,
   completed, overflow). Because the value carries no information, the census
   finds that **all 16 call sites discard it** (10 overwrite rax immediately, 6
   never read it) - see `caller_use.tsv`.
5. **There is no bounds check.** Nothing in the body compares the pointer with
   `limitPtr` (+0x18) or `start` before the rewind and the 8-byte read, so the
   preconditions `ptr >= limitPtr` (and a buffer at least 8 bytes past the new
   pointer) are entirely the caller's responsibility. The name says "internal",
   and this is the unchecked path; a bounds-checking sibling is a separate
   window.

The window does **not** begin with `endbr64` (the first instruction is the
`bitsConsumed` load), which is consistent with an internal static function that
is never an indirect-branch target - unlike the sibling varint windows in the
same binary.

Struct layout pinned by the offsets: `bitContainer` `+0x00` (8 bytes),
`bitsConsumed` `+0x08` (u32), `ptr` `+0x10` (pointer). The routine is a leaf: no
calls, no relocations, one `.eh_frame` FDE.

Return value: 0 (`BIT_DStream_unfinished` in zstd's enum - an inference from the
constant and the call sites, not from a symbol).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-zstd-bit-reload-dstream-internal-628f710-115")

START = 0x628F710
END = 0x628F732
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

def _rm(m, addr, size):
    return sum(m.mem.get(addr + i, 0) << (8 * i) for i in range(size))


def _wm(m, addr, value, size):
    for i in range(size):
        m.mem[(addr + i) & M64] = (value >> (8 * i)) & 0xFF


def reload(bits_consumed, word, ptr):
    """The routine's effect, in Python.

    Returns `(bitContainer, bitsConsumed, ptr, status)`: the container becomes
    the 8-byte little-endian word at the rewound pointer, `bitsConsumed` keeps
    only its sub-byte remainder, the pointer moves back by the whole bytes
    consumed, and the status is the constant 0.
    """
    advance = (bits_consumed & M32) >> BIT_SHIFT
    return (word & M64, bits_consumed & BIT_MASK, (ptr - advance) & M64,
            STATUS_UNFINISHED)


def reload_decoded(bits_consumed, word, ptr=0x40000000, struct=0x1000,
                   path=None):
    """Same effect, by executing the routine's own decoded bytes.

    The 8-byte word is seeded at the address the model predicts; if the routine
    computed a different rewind it would read uninitialised memory and the
    machine raises, so agreement is a real check rather than a tautology.
    """
    m = Machine([], 0, 0, 0)
    m.regs["rdi"] = struct
    _wm(m, struct + STRUCT_CONTAINER, 0xDEADBEEFDEADBEEF, 8)
    _wm(m, struct + STRUCT_BITS, bits_consumed & M32, 4)
    _wm(m, struct + STRUCT_PTR, ptr, 8)
    advance = (bits_consumed & M32) >> BIT_SHIFT
    _wm(m, (ptr - advance) & M64, word, 8)
    m = _execute(m, path)
    return (_rm(m, struct + STRUCT_CONTAINER, 8),
            _rm(m, struct + STRUCT_BITS, 4),
            _rm(m, struct + STRUCT_PTR, 8),
            m.get("rax"))


def access_addresses(bits_consumed, word, ptr=PTR_BASE, struct=0x1000,
                     path=None):
    """Every (address, size) the decoded run reads and writes.

    States the access claim positively: exactly one 8-byte load at the rewound
    pointer, and exactly three stores into the struct.
    """
    m = Machine([], 0, 0, 0)
    m.regs["rdi"] = struct
    advance = (bits_consumed & M32) >> BIT_SHIFT
    _wm(m, struct + STRUCT_CONTAINER, 0xDEADBEEFDEADBEEF, 8)
    _wm(m, struct + STRUCT_BITS, bits_consumed & M32, 4)
    _wm(m, struct + STRUCT_PTR, ptr, 8)
    _wm(m, (ptr - advance) & M64, word, 8)
    loads, stores = [], []
    real_load, real_store = m.load, m.store
    m.load = lambda a, size: (loads.append((a, size)), real_load(a, size))[1]
    m.store = lambda a, v, size: (stores.append((a, size)),
                                  real_store(a, v, size))[1]
    _execute(m, path)
    return loads, stores


# --- cases, ledger and evidence tables -------------------------------------

FAMILIES = ("sub_byte", "aligned", "mixed", "extreme")

# The four rows kept verbatim at the head of each family.
BOUNDARY_CASES = {
    "sub_byte": [0, 1, 7, 6],
    "aligned": [8, 0x10, 0x40, 0x8],
    "mixed": [9, 0xF, 0xFD, 0x123],
    "extreme": [0xFFFFFFFF, 0x80000000, 0x01000000, 0x00FFFFFF],
}

LEDGER_WORDS = {
    # one fixed, readable 8-byte word per boundary row
    ("sub_byte", 0): 0x1122334455667788,
    ("sub_byte", 1): 0x00FF00FF00FF00FF,
    ("sub_byte", 7): 0xFFFFFFFFFFFFFFFF,
    ("sub_byte", 6): 0x0000000000000000,
    ("aligned", 8): 0x1122334455667788,
    ("aligned", 0x10): 0x00FF00FF00FF00FF,
    ("aligned", 0x40): 0xFEDCBA9876543210,
    ("aligned", 0x8): 0x0000000000000001,
    ("mixed", 9): 0x1122334455667788,
    ("mixed", 0xF): 0x00FF00FF00FF00FF,
    ("mixed", 0xFD): 0xFFFFFFFFFFFFFFFE,
    ("mixed", 0x123): 0x8000000000000000,
    ("extreme", 0xFFFFFFFF): 0x1122334455667788,
    ("extreme", 0x80000000): 0x00FF00FF00FF00FF,
    ("extreme", 0x01000000): 0xAAAAAAAAAAAAAAAA,
    ("extreme", 0x00FFFFFF): 0x5555555555555555,
}


def _fill(rng, count, draw):
    return [draw(rng) for _ in range(count)]


def generate_cases(seed=115):
    """The full sweep: 2400 cases, 600 per family, the boundaries first."""
    import random
    rng = random.Random(seed)
    draws = {
        "sub_byte": lambda r: r.randrange(0, 8),
        "aligned": lambda r: 8 * r.randrange(0, 1 << 27),
        "mixed": lambda r: r.randrange(0, 1 << 16),
        "extreme": lambda r: r.choice([r.randrange(1 << 24, 1 << 31),
                                       r.randrange(1 << 31, 1 << 32)]),
    }
    out = []
    for name in FAMILIES:
        rows = [{"bits": b} for b in BOUNDARY_CASES[name]]
        while len(rows) < 600:
            rows.append({"bits": draws[name](rng)})
        assert len(rows) == 600, (name, len(rows))
        out.extend({"family": name, **r} for r in rows)
    for i, r in enumerate(out):
        r["word"] = rng.getrandbits(64)
    # pin the readable words on the boundary rows
    for r in out:
        key = (r["family"], r["bits"])
        if key in LEDGER_WORDS and r["word"] != LEDGER_WORDS[key]:
            r["word"] = LEDGER_WORDS[key]
    assert len(out) == 2400, len(out)
    return out


LEDGER_PER_FAMILY = 75


def _stride(seq, need):
    assert need <= len(seq), (need, len(seq))
    if need == len(seq):
        return list(seq)
    step = len(seq) / need
    return [seq[int(i * step)] for i in range(need)]


def _answer(case):
    return reload(case["bits"], case["word"], PTR_BASE)


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
        container, bits_after, new_ptr, status = _answer(r)
        r["bytes_consumed"] = r["bits"] >> BIT_SHIFT
        r["bits_after"] = bits_after
        r["new_ptr"] = new_ptr
        r["container"] = container
        r["status"] = status
        out[i] = r
    return out


def replay_case(case):
    """Re-derive a committed row: model and decoded execution must agree."""
    ans = _answer(case)
    got = reload_decoded(case["bits"], case["word"], PTR_BASE)
    assert ans == got, (case, ans, got)
    return ans


def _bytes(values):
    return "".join(f"{b:02x}" for b in values)


def cases_tsv_rows():
    rows = ["id\tfamily\tbits_consumed\tbytes_consumed\tbits_after\tnew_ptr"
            "\tcontainer\tstatus"]
    for r in ledger_rows():
        rows.append("\t".join([
            str(r["id"]), r["family"], hex(r["bits"]),
            str(r["bytes_consumed"]), str(r["bits_after"]),
            hex(r["new_ptr"]), hex(r["container"]), str(r["status"]),
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
