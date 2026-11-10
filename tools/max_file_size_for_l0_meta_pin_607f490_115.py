"""Model of node #115 rocksdb MaxFileSizeForL0MetaPin 0x607f490..0x607f4bb.

`rocksdb::MaxFileSizeForL0MetaPin(MutableCFOptions const&)`:

  _ZN7rocksdb23MaxFileSizeForL0MetaPinERKNS_16MutableCFOptionsE

The routine reads one field (the first 8 bytes of the options struct) and
returns three halves of it, truncated to an even half:

  result = 3 * (value >> 1)                    if value <= 0xAAAAAAAAAAAAAAAB
  result = 0xFFFFFFFFFFFFFFFF                  otherwise

Behaviour derived from the routine's own committed instruction bytes
(`main.txt`, hashed against the digest-verified artifact by `verify.py`):

  mov    (%rdi),%rdx          (0x607f494)  value = *(uint64_t *)rdi
  mov    $0xffffffffffffffff,%rax           default result is the -1 sentinel
  movabs $0xaaaaaaaaaaaaaaab,%rcx           the overflow threshold
  cmp    %rdx,%rcx / jb       (0x607f4a8/0x607f4ab)
                                            UNSIGNED rcx < value -> return -1
  mov    %rdx,%rax            (0x607f4ad)
  and    $0xfffffffffffffffe,%rdx           drop the low bit: 2*(value>>1)
  shr    $1,%rax              (0x607f4b4)   value>>1
  add    %rdx,%rax            (0x607f4b7)   (value>>1) + 2*(value>>1) = 3*(value>>1)

Three build-specific details follow from those bytes and are exercised by
the ledger:

1. The guard compares with `jb`, i.e. **unsigned**: the sentinel is returned
   exactly when `0xAAAAAAAAAAAAAAAB < value`, so the largest accepted input is
   `0xAAAAAAAAAAAAAAAB` itself, whose result `0x10000000000000001 - 2` still
   fits in 64 bits.
2. The halving happens **before** the multiply, so an odd input is truncated:
   `3 * (value >> 1)`, not `(3 * value) >> 1`.
3. The low-bit clear (`and $-2`) and the shift are the *same* halving applied
   twice -- `2*(value>>1)` and `(value>>1)` -- which is what makes the add a
   multiply by three rather than by two.

The function is a leaf: no calls, no stores, no relocations, and the whole
body is one `.eh_frame` FDE (0x607f490..0x607f4bb, 43 bytes). The table below
is the only memory it reads apart from the single `(%rdi)` field.

Callers (12, see the packet's `callers.tsv` / `caller_use.tsv`): 4 push the
result as a stack argument, 4 copy it into a register for later use, 3 spill
it to the stack and 1 overwrites `rax` before reading it, so the value is
dead at that one call site -- a reconstruction that assumed all twelve
consume the result would be wrong there.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-rocksdb-max-file-size-for-l0-meta-pin-607f490-115")

START = 0x607F490
END = 0x607F4BB
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

M64 = (1 << 64) - 1
GUARD = 0xAAAAAAAAAAAAAAAB          # 0x607f49e..0x607f4a5 movabs
SENTINEL = M64                     # 0x607f497 mov $0xffffffffffffffff,%rax
FIELD_OFFSET = 0x0                 # mov (%rdi),%rdx reads *rdi exactly


def max_file_size_for_l0_meta_pin(value):
    """Closed form: 3 * (value >> 1), or the -1 sentinel past the guard."""
    value &= M64
    if value > GUARD:
        return SENTINEL
    return (3 * (value >> 1)) & M64


# objdump wraps a long instruction's bytes onto a continuation line that has
# an address and bytes but no mnemonic; `LINE` keeps the mnemonic optional so
# those lines can be folded into the instruction they belong to.
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
    """The routine's committed bytes, decoded: every line of `main.txt` whose
    address lies inside [START, END). Memoized: the differential calls this
    once per value."""
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
        raw = bytes.fromhex(m.group(2).replace(" ", ""))
        if not (START <= addr < END):
            continue
        if m.group(3) is None:          # continuation of the previous line
            assert out and out[-1].addr + len(out[-1].raw) == addr, hex(addr)
            out[-1].raw += raw
            continue
        text = m.group(3).strip()
        parts = text.split(None, 1)
        out.append(Ins(addr, raw, parts[0], parts[1] if len(parts) > 1 else ""))
    _STREAM_CACHE[key] = out
    return out


# --- a small machine model for exactly the instructions this routine uses ---

_R8 = {"al": "rax", "dil": "rdi", "r8b": "r8"}
_IMM = re.compile(r"^\$(-?0x[0-9a-f]+|-?\d+)$")
_DISP = re.compile(r"^(?:(0x[0-9a-f]+|\d+))?\((%r[a-z0-9]+)\)$")


def _canon(reg):
    reg = reg.strip().lstrip("%")
    if reg in _R8:
        return _R8[reg]
    for wide, narrows in (("rax", ("eax", "ax")), ("rdx", ("edx", "dx")),
                          ("rcx", ("ecx", "cx")), ("rdi", ("edi", "di")),
                          ("rsi", ("esi", "si"))):
        if reg == wide or reg in narrows:
            return wide
    return reg


def _imm(op):
    m = _IMM.match(op.strip())
    return int(m.group(1), 0) & M64 if m else None


def max_file_size_for_l0_meta_pin_decoded(value, path=None):
    """Execute the routine's own decoded instructions.

    Raises AssertionError on any instruction this model does not implement,
    so the emulator can never silently agree by accident.
    """
    insns = instruction_stream(path)
    assert insns, "empty instruction stream"
    regs = {"rdi": 0, "rax": 0, "rdx": 0, "rcx": 0}
    mem = {0: value & M64}
    by_addr = {i.addr: n for n, i in enumerate(insns)}
    pc = 0
    cf = False
    steps = 0
    while True:
        steps += 1
        assert steps <= 100, "no termination"
        assert pc < len(insns), "ran off the end of the routine"
        ins = insns[pc]
        mn, ops = ins.mnemonic, [o.strip() for o in ins.op_str.split(",") if o.strip()]
        pc += 1
        if mn in ("endbr64", "nop", "int3", "hlt"):
            continue
        if mn in ("mov", "movabs"):
            src, dst = ops
            s = _imm(src)
            d = _DISP.match(src)
            if d:
                base = _canon(d.group(2))
                off = int(d.group(1), 0) if d.group(1) else 0
                assert base == "rdi" and off == FIELD_OFFSET, (ins,)
                stored = mem[off]
                if _canon(dst) in ("rax", "eax"):
                    stored &= 0xFFFFFFFF
                regs[_canon(dst)] = stored & M64
            elif s is not None:
                regs[_canon(dst)] = s & M64
            else:
                regs[_canon(dst)] = regs[_canon(src)] & M64
            continue
        if mn == "cmp":
            a = _imm(ops[0])
            if a is None:
                a = regs[_canon(ops[0])]
            b = regs[_canon(ops[1])]
            cf = (b & M64) < (a & M64)
            continue
        if mn in ("jb", "jae", "je", "jne"):
            assert mn in ("jb", "jae"), \
                f"branch {mn} is not part of this routine: {ins}"
            target = int(ops[0].split()[0], 16)
            take = cf if mn == "jb" else not cf
            if take:
                assert target in by_addr, (ins, "target outside the routine")
                pc = by_addr[target]
            continue
        if mn in ("and", "or", "xor", "add", "sub", "shl", "shr", "sar"):
            src, dst = ops
            d = _canon(dst)
            s = _imm(src)
            if s is None:
                s = regs[_canon(src)] & M64
            cur = regs[d] & M64
            if mn == "and":
                out = cur & s
            elif mn == "or":
                out = cur | s
            elif mn == "xor":
                out = cur ^ s
            elif mn == "add":
                out = cur + s
            elif mn == "sub":
                out = cur - s
            elif mn == "shl":
                out = cur << s
            elif mn == "shr":
                out = cur >> s
            else:
                out = cur >> s
            regs[d] = out & M64
            continue
        if mn == "ret":
            return regs["rax"] & M64
        raise AssertionError(f"unimplemented instruction: {ins}")


# --- cases, ledger and evidence tables -------------------------------------

def _family_boundary():
    """Both sides of the guard, tightly: the sentinel boundary is the one
    place where an off-by-one in the comparison changes the answer."""
    vals = [0, 1, 2, 3, 4, 5, M64, M64 - 1, 1 << 63, (1 << 63) - 1]
    for k in range(0, 295):
        vals += [GUARD - k, GUARD + k]
    return [{"family": "boundary", "value": v & M64} for v in vals]


def _family_small():
    return [{"family": "small", "value": v} for v in range(600)]


def _family_parity():
    """Odd inputs, where `3*(v>>1)` and `(3*v)>>1` disagree by one."""
    vals = []
    base = 1 << 62
    for i in range(0, 600, 2):
        vals += [base + i, base + i + 1]
    return [{"family": "parity", "value": v & M64} for v in vals]


def _family_random(seed, n=600):
    import random
    rng = random.Random(seed)
    return [{"family": "random", "value": rng.getrandbits(64)} for _ in range(n)]


def generate_cases(seed=115):
    """The full sweep: 2400 cases over four families."""
    fams = [("boundary", _family_boundary()), ("small", _family_small()),
            ("parity", _family_parity()), ("random", _family_random(seed))]
    out = []
    for name, rows in fams:
        assert len(rows) == 600, (name, len(rows))
        out.extend(rows)
    return out


LEDGER_TARGET = 300


def _stride(seq, need):
    assert need <= len(seq), (need, len(seq))
    if need == len(seq):
        return list(seq)
    step = len(seq) / need
    return [seq[int(i * step)] for i in range(need)]


def ledger_rows(rows=None):
    """A ~300-case stratified, reviewable subset of the sweep."""
    rows = list(rows) if rows is not None else generate_cases()
    fams = {}
    for r in rows:
        fams.setdefault(r["family"], []).append(r)
    per = LEDGER_TARGET // max(1, len(fams))
    out = []
    for name in sorted(fams):
        out.extend(_stride(fams[name], per))
    for n, r in enumerate(out, 1):
        r = dict(r)
        r["id"] = n
        r["expected"] = max_file_size_for_l0_meta_pin(r["value"])
        out[n - 1] = r
    return out


def replay_case(case):
    return max_file_size_for_l0_meta_pin(case["value"])


def cases_tsv_rows():
    rows = ["id\tfamily\tvalue\texpected\tthe_sentinel\taccepted"]
    for r in ledger_rows():
        rows.append("\t".join([
            str(r["id"]), r["family"], hex(r["value"]), hex(r["expected"]),
            "1" if r["expected"] == SENTINEL else "0",
            "0" if r["value"] > GUARD else "1",
        ]))
    return rows


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "gen-cases":
        (PACKET / "cases.tsv").write_text("\n".join(cases_tsv_rows()) + "\n")
        print(f"wrote {PACKET / 'cases.tsv'}")
        return 0
    print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main())
