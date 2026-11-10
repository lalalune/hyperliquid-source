"""Model of node #115 libz `zmemcpy` 0x630c430..0x630c558 (296 bytes).

`void zmemcpy(Bytef* dest, const Bytef* source, uInt len)` — zlib's
flat-memory copy helper. The routine has no return value: its contract is the
bytes it writes to `dest`.

Behaviour read off the routine's own committed instruction bytes (`main.txt`,
hashed against the digest-verified artifact by `verify.py`):

  len == 0                       (0x630c439 test %edx,%edx ; je 0x630c471)
     -> return without touching anything

  len <= 7                       (0x630c43d lea -1(%rdx),%edx ; cmp $6 ;
                                  0x630c443 jbe 0x630c455)
     -> the byte-at-a-time loop at 0x630c460

  dest - source in 1..15         (0x630c445 lea 0x1(%rsi) ; 0x630c449 mov %rdi,%rcx
                                  ; 0x630c44c sub %rsi,%rcx ; 0x630c44f cmp $0xe
                                  ; 0x630c453 ja 0x630c478)
     -> ALSO the byte-at-a-time loop

  otherwise                      -> the 16-byte `movdqu`/`movups` chunk loop at
                                    0x630c490 followed by a byte-wise tail

The third condition is the interesting one, and it is why this window is not
just "memcpy": the compiler emits a **forward byte loop exactly when the
destination starts inside the source within 15 bytes** (`0 < dest-source <= 15`),
because a 16-byte chunk copy would read chunks that the previous store already
overwrote. The byte loop instead produces the classic forward-repeat result
byte by byte, so an overlapping call behaves the way a forward `memcpy` does
rather than moving stale chunks. The `sub`/`cmp` pair is unsigned, so every
case with `dest <= source` (including `dest < source`, where the difference
wraps) falls through to the chunk loop — which is safe because the chunk loop
copies forward.

Both paths are modelled here: `zmemcpy_path` returns which path the bytes
select, and `zmemcpy` replays the selected path against a buffer that mirrors
the reads and writes the real memory would see.

Callers: 44 direct call sites (see `callers.tsv`). The routine is **void**, so
`caller_use.tsv`'s post-call `rax` classification is deliberately NOT presented
as a returned-value contract: it records what each caller does with `rax`
afterwards, which here is the caller's own reuse of the register (42 sites
write `rax` before reading it, 2 never read it again). The evidence for the
caller contract is the record of what each site does next, not a value it
receives.

Callers (see the packet's `callers.tsv` / `caller_use.tsv`). The routine is a
leaf with no calls and no relocations, and the whole body is one `.eh_frame`
FDE.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-libz-zmemcpy-630c430-115")

START = 0x630C430
END = 0x630C558
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

M64 = (1 << 64) - 1
SMALL_MAX = 7          # len-1 <= 6 at 0x630c440
OVERLAP_MAX = 15       # dest-source <= 15 keeps the byte loop; 0x630c44f cmp $0xe
TAIL_MAX = 15          # len-1 <= 14 skips the chunk loop; 0x630c478 cmp $0xe
CHUNK = 16


def zmemcpy_path(length, distance):
    """Which path the routine's own guard selects.

    `distance` is `dest - source` as an unsigned 64-bit difference, exactly as
    the `sub %rsi,%rcx` at 0x630c44c computes it.
    """
    if length == 0:
        return "empty"
    if length - 1 <= SMALL_MAX - 1:            # len <= 7
        return "byte"
    diff = (distance - 1) & M64                 # dest - (source + 1)
    if diff <= OVERLAP_MAX - 1:                # dest - source in 1..15
        return "byte"
    return "vector"


def _pad(buf, need):
    if len(buf) < need:
        buf.extend([0] * (need - len(buf)))


def zmemcpy(source, length, distance):
    """Replay the selected path over a buffer and return the `length` bytes
    written at `distance`.

    `source` is the buffer's initial contents as a list of bytes; the buffer is
    extended with zeros as needed. Reads observe writes, as the real routine's
    do, which is what makes the overlapping case meaningful.
    """
    if length == 0:
        return []
    buf = list(source)
    _pad(buf, distance + length)
    path = zmemcpy_path(length, distance)
    if path == "byte":
        for i in range(length):
            buf[distance + i] = buf[i]
    else:
        done = 0
        chunks = 0 if length - 1 <= TAIL_MAX - 1 else (length // CHUNK) * CHUNK
        while done < chunks:
            # movdqu loads all 16 bytes, then movups stores them: the chunk is
            # snapshotted, so an overlapping store does NOT feed the load.
            snap = buf[done:done + CHUNK]
            for i in range(CHUNK):
                buf[distance + done + i] = snap[i]
            done += CHUNK
        while done < length:
            buf[distance + done] = buf[done]
            done += 1
    return buf[distance:distance + length]


def zmemcpy_counterfactual(source, length, distance):
    """The same copy forced through the chunk path.

    Used only to show, in the ledger, the bytes the guard prevents: for an
    overlapping call this differs from `zmemcpy`.
    """
    if length == 0:
        return []
    buf = list(source)
    _pad(buf, distance + length)
    done = 0
    while done < length:
        step = min(CHUNK, length - done)
        snap = buf[done:done + step]          # snapshot the chunk first
        for i in range(step):
            buf[distance + done + i] = snap[i]
        done += step
    return buf[distance:distance + length]


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


def zmemcpy_decoded(length, distance, path=None, src_bytes=None):
    """Execute the routine's own decoded bytes against a buffer.

    Returns the `length` bytes it writes at `distance` relative to the source
    pointer, so the result can be compared with `zmemcpy` directly. Raises
    AssertionError on any instruction this model does not implement.
    """
    n_src = max(length, distance + length) + CHUNK
    buf = list(src_bytes) if src_bytes is not None else \
        [(i * 7 + 1) & 0xFF for i in range(n_src)]
    _pad(buf, n_src)
    insns = instruction_stream(path)
    by_addr = {i.addr: k for k, i in enumerate(insns)}
    m = Machine(buf, dest=distance, source=0, length=length)
    # seed the CANONICAL 64-bit names: the accessors canonicalise sub-registers
    # (%edx -> rdx), so seeding "edx" directly would never be read.
    m.regs["rdi"] = distance                 # dest = source + distance
    m.regs["rsi"] = 0
    m.regs["rdx"] = length & 0xFFFFFFFF
    pc = 0
    flags = {}
    steps = 0
    while True:
        steps += 1
        assert steps <= 20000, "no termination"
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
                m.set(dst, m.load(m.addr_of(src), 16))     # load
            elif _MEM.match(dst):
                m.store(m.addr_of(dst), m.get(src), 16)    # store 16 bytes
            else:
                m.set(dst, m.get(src))
            continue
        if mn == "mov":
            src, dst = ops
            imm = _IMM.match(src)
            if _MEM.match(dst):                      # a store
                size = _width(src) // 8
                value = (int(imm.group(1), 0) if imm else m.get(src))
                m.store(m.addr_of(dst), value, size)
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
            val = m.load(m.addr_of(src), size)
            if mn == "movsbl" and val & 0x80:
                val -= 0x100
            if mn == "movslq" and val & 0x80000000:
                val -= 0x100000000
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
            return [m.load(distance + i, 1) for i in range(length)]
        raise AssertionError(f"unimplemented instruction: {ins}")


# --- cases, ledger and evidence tables -------------------------------------

def _pattern(k, seed=0):
    return [(i * 7 + 1 + seed * 31) & 0xFF for i in range(k)]


def generate_cases(seed=115):
    """The full sweep: 2400 cases over four families."""
    import random
    rng = random.Random(seed)
    n = 600
    fams = {}
    # empty: len == 0
    fams["empty"] = [{"family": "empty", "length": 0, "distance": 0,
                      "src": _pattern(4)} for _ in range(n)]
    # small: len in 1..7, the byte loop
    fams["small"] = [{"family": "small", "length": rng.randrange(1, 8),
                      "distance": rng.choice([0, 1, 3, 15, 16, 64]),
                      "src": _pattern(96, rng.randrange(97))} for _ in range(n)]
    # overlap: 1 <= dest-source <= 15, which the guard sends to the byte loop
    fams["overlap"] = [{"family": "overlap", "length": rng.randrange(8, 129),
                        "distance": rng.randrange(1, 16),
                        "src": _pattern(160, rng.randrange(97))}
                       for _ in range(n)]
    # vector: len >= 8 and no overlap in either direction
    fams["vector"] = [{"family": "vector",
                       "length": rng.randrange(8, 257),
                       "distance": rng.choice([16, 17, 31, 32, 64, 200]),
                       "src": _pattern(520, rng.randrange(97))}
                      for _ in range(n)]
    out = []
    for name in ("empty", "small", "overlap", "vector"):
        assert len(fams[name]) == n, (name, len(fams[name]))
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
    """Shorten a sweep case for the committed ledger while keeping the path it
    selects (so the table still shows both the byte and the vector path)."""
    fam, length, distance = case["family"], case["length"], case["distance"]
    if fam == "empty":
        return {"family": fam, "length": 0, "distance": 0, "src": []}
    if fam == "small":
        length = min(max(length, 1), SMALL_MAX)          # stays on the byte path
    elif fam == "overlap":
        length = min(max(length, SMALL_MAX + 1), 32)     # 8..32, guard -> byte
    else:
        length = min(max(length, CHUNK), 32)             # >= 16 and no overlap
    return {"family": fam, "length": length, "distance": distance,
            "src": case["src"][:length]}


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
        r["path"] = zmemcpy_path(r["length"], r["distance"])
        r["expected"] = zmemcpy(r["src"], r["length"], r["distance"])
        r["counterfactual"] = zmemcpy_counterfactual(
            r["src"], r["length"], r["distance"])
        out[i] = r
    return out


def replay_case(case):
    return zmemcpy(case["src"], case["length"], case["distance"])


def _bytes(values):
    return "".join(f"{b:02x}" for b in values)


def cases_tsv_rows():
    rows = ["id\tfamily\tlen\tdistance\tpath\tsrc\texpected\tvector_only_differs"]
    for r in ledger_rows():
        rows.append("\t".join([
            str(r["id"]), r["family"], str(r["length"]), str(r["distance"]),
            r["path"], _bytes(r["src"]), _bytes(r["expected"]),
            "1" if r["expected"] != r["counterfactual"] else "0",
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
