"""Model of node #115 zstd-sys `ZSTD_count_2segments` 0x6248790..0x624899a.

    size_t ZSTD_count_2segments(const BYTE *ip, const BYTE *match,
                               const BYTE *iEnd, const BYTE *mEnd,
                               const BYTE *mStart)

A two-segment match counter: it counts how many bytes `ip` and `match` agree on,
but `match` points into the *dictionary tail*, which ends at `mEnd`. If both
cursors reach `mEnd` while still agreeing, the match cursor wraps back to
`mStart` and counting continues against the start of the current block. The
routine returns the number of **input** bytes matched (never a match-side
distance), and it writes nothing.

Register roles read off the routine's own committed bytes (`main.txt`, hashed
against the digest-verified artifact by `verify.py`):

    rdi = ip     rsi = match     rdx = iEnd     rcx = mEnd     r8 = mStart

  6248790  mov %rdx,%r9                              (no endbr64: no CET landing pad)
  6248793  mov %rcx,%rdx; 6248797 mov %rcx,%r10     rdx = r10 = mEnd
  624879a  sub %rsi,%rdx; 624879e add %rdi,%rdx     rdx = ip + (mEnd - match)
  62487a1  cmp %rdx,%r9;  62487a4 cmovbe %r9,%rdx   rdx = min(iEnd, ip+(mEnd-match))
  62487a8  lea -0x7(%rdx),%rbx                      rbx = vEnd - 7
  62487ac  cmp %rbx,%rdi; 62487af jae 0x6248830     ip < vEnd-7 -> 8-byte loop
  62487b7  cmp %rax,%rcx; 62487ba jne 0x6248898     the first 8 bytes differ
  62487c8  cmp %rbx,%r11; 62487cb jae 0x6248836     fewer than 8 left: dword tail
  62487e1  tzcnt %rax,%rcx; 62487e6 shr $0x3,%eax   first differing byte in the word
  62487e9  add %r11,%rax; 62487ec sub %rdi,%rax     rax = input-side matched bytes
  62487f3  cmp %r10,%rdx; 62487f6 jne 0x6248874     match+len != mEnd -> return len
  62487f8  add %rdi,%rax                            wrap: ip += len1
  62487fb  lea -0x7(%r9),%rsi                       second segment is bounded by iEnd
  6248836  lea -0x3(%rdx),%rcx / cmp / jae          dword tail when 4 bytes fit
  624884a  lea -0x1(%rdx),%rcx / cmp / jae          word tail when 2 bytes fit
  6248860  cmp %rdx,%r11; 6248863 jb 0x6248880      else the byte tail
  6248880  movzx (%r11),%ebx; cmp (%rax),%bl        dword/word/byte compares
  6248886  sete %al; 624888c add %r11,%rax          advance by 1 iff equal
  62488a8  ...                                      phase 2 repeats the same shape
  62488e8  sub %rdi,%rdx; 62488eb jmp 0x6248822     total = len1 + (cursor - ip)
  6248825  pop %rbx; 6248827 ret

Behaviour: `vEnd = min(iEnd, ip + (mEnd - match))`; phase 1 counts the agreeing
bytes of `(ip, match)` up to `vEnd`; if the cursors did not reach `mEnd` the
count is returned as is, otherwise the match cursor restarts at `mStart` and
phase 2 counts the agreeing bytes of `(ip+len1, mStart)` up to `iEnd`, and
`len1 + len2` is returned.

Build-specific details pinned by the anchors in `semantics.tsv`:

1. the bound is an **unsigned** `cmovbe` on two pointers, so a pointer with bit
   63 set is never mistaken for a negative value;
2. the first differing byte inside a word is found with `tzcnt` (BMI1), not
   `bsf`; every `tzcnt` site is preceded by a `cmp`/`je`/`jne` on the same two
   words, so the zero case cannot occur, but the instruction chosen is the
   zero-safe one;
3. the fast loops are entered only when a whole 8-byte, 4-byte or 2-byte read
   fits below `vEnd` (`ip < vEnd-7`, `cursor < vEnd-3`, `cursor < vEnd-1`), so no
   read crosses `vEnd`; a `vEnd` below 7 makes `vEnd-7` wrap to a huge value,
   which merely fails the *unsigned* `jae` and falls back to the byte tail;
4. the byte tail advances the cursor by `sete` (1 on agreement, 0 otherwise),
   which is what makes it stop at the first difference;
5. the return value is the input-side length: every exit computes `cursor - ip`,
   and the phase-2 exits use the `ip` already advanced by `len1`;
6. phase 2 uses `r8` (mStart) as its only match-side cursor and `r10` (mEnd)
   only for the wrap test - neither is modified by phase 1;
7. the routine is a leaf that writes nothing: there are no stores at all, only
   loads, and its two `push`/`pop` pairs balance.

The window is one `.eh_frame` FDE, no calls, no relocations, `raw_equal` with 3
identical source objects (see the vendor census record in `records.json`). The
routine does **not** start with `endbr64`: it is a static function with no CET
landing pad, and the four bytes immediately below it are `cc cc cc cc` (int3
padding), which confirms that `0x6248790` is a real function start rather than a
cut into a larger body.
"""

from __future__ import annotations

import re
import sys

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-zstd-count-2segments-6248790-115")

START = 0x6248790
END = 0x624899A
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

M64 = (1 << 64) - 1
M32 = (1 << 32) - 1

IP_BASE = 0x200000      # the modelled input region   (ip .. iEnd)
MATCH_BASE = 0x300000   # the modelled dictionary tail (mStart .. mEnd)
PAD = 64                # slack for the whole-word fast loops


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

    def __repr__(self):                       # pragma: no cover - debug aid
        return f"<{self.addr:#x} {self.mnemonic} {self.op_str}>"


def split_ops(text):
    """Split an operand list on commas at bracket depth zero."""
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


_SIZES = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "xmmword": 16}


def mem_size(ins):
    """The access width of the instruction's memory operand, in bytes."""
    m = re.search(r"\b(byte|word|dword|qword|xmmword) ptr", ins.op_str)
    return _SIZES[m.group(1)] if m else 0


_WIDTH = {"rax": 64, "eax": 32, "ax": 16, "al": 8, "ah": 8,
          "rdx": 64, "edx": 32, "dx": 16, "dl": 8,
          "rcx": 64, "ecx": 32, "cx": 16, "cl": 8,
          "rdi": 64, "edi": 32, "di": 16, "dil": 8,
          "rsi": 64, "esi": 32, "si": 16, "sil": 8,
          "r8": 64, "r8d": 32, "r8w": 16, "r8b": 8,
          "r9": 64, "r9d": 32, "r9w": 16, "r9b": 8,
          "r10": 64, "r10d": 32, "r10w": 16, "r10b": 8,
          "r11": 64, "r11d": 32, "r11w": 16, "r11b": 8,
          "rbx": 64, "ebx": 32, "bx": 16, "bl": 8,
          "rbp": 64, "ebp": 32, "bp": 16, "bpl": 8,
          "rsp": 64, "esp": 32}
_CANON = {"eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
          "edx": "rdx", "dx": "rdx", "dl": "rdx",
          "ecx": "rcx", "cx": "rcx", "cl": "rcx",
          "edi": "rdi", "di": "rdi", "dil": "rdi",
          "esi": "rsi", "si": "rsi", "sil": "rsi",
          "r8d": "r8", "r8w": "r8", "r8b": "r8",
          "r9d": "r9", "r9w": "r9", "r9b": "r9",
          "r10d": "r10", "r10w": "r10", "r10b": "r10",
          "r11d": "r11", "r11w": "r11", "r11b": "r11",
          "ebx": "rbx", "bx": "rbx", "bl": "rbx",
          "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
          "esp": "rsp"}
_IMM = re.compile(r"^\$(-?0x[0-9a-f]+|-?\d+)$")
_MEM = re.compile(r"^(?:(-?0x[0-9a-f]+|-?\d+))?\((%[a-z0-9]+)"
                  r"(?:,(%[a-z0-9]+),(\d+))?\)$")
_XMM = re.compile(r"^%xmm(\d+)$")
_16B = ("movdqu", "movdqa", "movups", "movaps")

_HANDLED = ("mov", "lea", "movzbl", "movzwl", "movsbl", "movslq", "add",
            "sub", "and", "or", "xor", "shl", "shr", "sar", "cmp", "test",
            "tzcnt", "jmp", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe",
            "js", "jl", "jle", "jg", "jge", "ret", "endbr64", "nop", "nopl",
            "nopw", "int3", "push", "pop", "sete", "setne", "setb", "setae",
            "cmovbe", "cmovb", "cmova", "cmovae", "cmove", "cmovne") + _16B


def _reg(reg):
    reg = reg.strip().lstrip("%")
    if _XMM.match("%" + reg):
        return "xmm" + reg[3:]
    return _CANON.get(reg, reg)


def _width(reg):
    reg = reg.strip().lstrip("%")
    return _WIDTH.get(reg, 128 if reg.startswith("xmm") else 64)


class Machine:
    """Byte-addressed memory, 64-bit registers, a small stack and 128-bit
    xmm lanes. Reads of uninitialised memory are an error, so a model that
    wanders outside the seeded regions cannot pass silently."""

    def __init__(self, buffer=b"", dest=0, source=0):
        self.mem = {i: b for i, b in enumerate(buffer)}
        self.regs = {"rax": 0, "rdx": 0, "rcx": 0, "rdi": dest, "rsi": source,
                     "r8": 0, "r9": 0, "r10": 0, "r11": 0, "rbx": 0, "rbp": 0,
                     "rsp": 0, "xmm0": 0, "xmm1": 0}
        self.stack = []
        self.pushes = 0
        self.pops = 0

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

    def val(self, op, size=None):
        """An operand's value: immediate, register (masked to `size` bytes if
        given) or a memory read of `size` bytes."""
        op = op.strip()
        imm = _IMM.match(op)
        if imm:
            v = int(imm.group(1), 0)
            return v if size is None else v & ((1 << (8 * size)) - 1)
        if _MEM.match(op):
            return self.load(self.addr_of(op), size or 8)
        return self.get(op) if size is None \
            else self.get(op) & ((1 << (8 * size)) - 1)


def _execute(m, path=None):
    """Run the routine's decoded bytes until it returns; hand back the machine.

    Raises AssertionError on any instruction this model does not implement, so a
    silently wrong model cannot pass the differential.
    """
    insns = instruction_stream(path)
    by_addr = {i.addr: k for k, i in enumerate(insns)}
    pc = 0
    flags = {}
    steps = 0
    while True:
        steps += 1
        assert steps <= 200000, "no termination"
        assert pc < len(insns), "ran off the end of the routine"
        ins = insns[pc]
        mn = ins.mnemonic
        # objdump writes AT&T size suffixes on memory operands (`movl`, `shrw`)
        # that Capstone folds into the operand width; normalise them so the
        # dispatch below can match on the bare mnemonic.
        if mn not in _HANDLED and mn[:-1] in _HANDLED:
            mn = mn[:-1]
        ops = split_ops(ins.op_str)
        pc += 1
        if mn in ("endbr64", "nop", "nopl", "nopw", "int3"):
            continue
        if mn == "push":
            m.stack.append(m.val(ops[0], 8))
            m.pushes += 1
            m.regs["rsp"] = (m.regs["rsp"] - 8) & M64
            continue
        if mn == "pop":
            assert m.stack, f"pop without a matching push: {ins}"
            m.set(ops[0], m.stack.pop())
            m.pops += 1
            m.regs["rsp"] = (m.regs["rsp"] + 8) & M64
            continue
        if mn in ("test", "cmp"):
            # the operand width matters: this routine compares bytes, words and
            # dwords in memory as well as whole registers.
            if _MEM.match(ops[0]) and _MEM.match(ops[1]):
                w = (mem_size(ins) or 8) * 8
            elif _MEM.match(ops[0]) or _MEM.match(ops[1]):
                # objdump omits the size suffix on a memory operand when a
                # register fixes it (`cmp %bx,(%rax)`), so take the width from
                # the other operand in that case.
                other = ops[1] if _MEM.match(ops[0]) else ops[0]
                w = (mem_size(ins) or _width(other) // 8) * 8
            elif _IMM.match(ops[0]):
                w = _width(ops[1])
            else:
                w = _width(ops[0])
            mask = (1 << w) - 1
            a = m.val(ops[0], w // 8) & mask
            b = m.val(ops[1], w // 8) & mask
            if mn == "test":                 # AND: ZF set when (a & b) == 0
                r, flags["cf"] = a & b, False
            else:                            # CMP a,b computes b - a
                r, flags["cf"] = (b - a) & mask, b < a
            flags["zf"] = r == 0
            flags["sf"] = (r >> (w - 1)) & 1
            # signed overflow, needed by the jl/jle/jg/jge family
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
        if mn.startswith("cmov"):
            src, dst = ops
            take = {"cmovbe": flags.get("cf") or flags.get("zf"),
                    "cmovb": flags.get("cf"),
                    "cmova": (not flags.get("cf")) and (not flags.get("zf")),
                    "cmovae": not flags.get("cf"),
                    "cmove": flags.get("zf"),
                    "cmovne": not flags.get("zf")}[mn]
            if take:
                m.set(dst, m.val(src, _width(dst) // 8))
            continue
        if mn in ("sete", "setne", "setb", "setae"):
            take = {"sete": flags.get("zf"), "setne": not flags.get("zf"),
                    "setb": flags.get("cf"), "setae": not flags.get("cf")}[mn]
            m.set(ops[0], 1 if take else 0)
            continue
        if mn == "tzcnt":
            src, dst = ops
            w = _width(dst)
            v = m.val(src, w // 8) & ((1 << w) - 1)
            # BMI1: the operand width when the source is zero (unlike bsf)
            m.set(dst, w if v == 0 else (v & -v).bit_length() - 1)
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

def geometry(n, tail, dist):
    """The modelled pointer set: an input window of `n` bytes, a dictionary
    tail of `tail` bytes whose end is `mEnd`, and `mStart` `dist` bytes before
    the match pointer."""
    return {"ip": IP_BASE, "iend": IP_BASE + n,
            "match": MATCH_BASE, "mend": MATCH_BASE + tail,
            "mstart": MATCH_BASE - dist}


def count_2segments(mem, g):
    """The routine's effect, in Python: `(total, len1, len2, reached_mend)`.

    `mem` maps address -> byte; `g` is a `geometry()`. Phase 1 counts the
    agreeing bytes of `(ip, match)` below `vEnd = min(iEnd, ip+(mEnd-match))`; if
    the cursors reach `mEnd`, phase 2 counts the agreeing bytes of
    `(ip+len1, mStart)` below `iEnd`. The total is the input-side length.
    """
    ip, match = g["ip"], g["match"]
    vEnd = min(g["iend"], ip + (g["mend"] - match))
    len1 = 0
    while ip + len1 < vEnd and mem[ip + len1] == mem[match + len1]:
        len1 += 1
    reached_mend = (match + len1 == g["mend"])
    if not reached_mend:
        return len1, len1, 0, False
    len2 = 0
    while ip + len1 + len2 < g["iend"] \
            and mem[g["mstart"] + len2] == mem[ip + len1 + len2]:
        len2 += 1
    return len1 + len2, len1, len2, True


def _run(mem, g, path=None, capture=False):
    m = Machine()
    for addr, byte in mem.items():
        m.mem[addr] = byte
    m.regs.update({"rdi": g["ip"], "rsi": g["match"], "rdx": g["iend"],
                   "rcx": g["mend"], "r8": g["mstart"]})
    loads, stores = [], []
    if capture:
        real_load, real_store = m.load, m.store
        m.load = lambda a, size: (loads.append((a, size)),
                                  real_load(a, size))[1]
        m.store = lambda a, v, size: (stores.append((a, size)),
                                      real_store(a, v, size))[1]
    m = _execute(m, path)
    assert m.pushes == m.pops, (m.pushes, m.pops)
    assert not m.stack, m.stack
    if capture:
        return m, loads, stores
    return m


def count_2segments_decoded(mem, g, path=None):
    """The same count, by executing the routine's own decoded bytes."""
    return _run(mem, g, path).get("rax")


def accesses(mem, g, path=None):
    """`(loads, stores)` - every memory access the decoded run performs, as
    `(address, size)`. The routine writes nothing, so `stores` is empty."""
    _, loads, stores = _run(mem, g, path, capture=True)
    return loads, stores


# --- cases, ledger and evidence tables -------------------------------------

FAMILIES = ("prefix", "wrap", "wrap_iend", "empty_tail", "iend_first")

# The rows kept verbatim at the head of each family: (n, tail, dist, plant1,
# plant2) - see `plant()` for what the two counts plant.
BOUNDARY_CASES = {
    "prefix": [(8, 16, 16, 0, 0), (8, 16, 16, 1, 0), (16, 8, 16, 7, 0),
               (4, 4, 8, 3, 0)],
    "wrap": [(16, 4, 16, 4, 0), (16, 4, 16, 4, 1), (32, 8, 40, 8, 3),
             (16, 1, 16, 1, 7)],
    "wrap_iend": [(8, 4, 16, 4, 4), (12, 4, 16, 4, 8), (40, 8, 48, 8, 32),
                  (9, 1, 16, 1, 8)],
    "empty_tail": [(8, 0, 8, 0, 0), (8, 0, 8, 0, 1), (16, 0, 16, 0, 15),
                   (9, 0, 16, 0, 9)],
    "iend_first": [(4, 16, 16, 4, 0), (8, 8, 16, 8, 0), (1, 1, 8, 1, 0),
                   (7, 8, 8, 7, 0)],
}


def plant(mem, rng, n, tail, dist, plant1, plant2):
    """Seed the two regions with random bytes and then plant the case:
    `plant1` agreeing bytes between `ip` and `match`, and - when that reaches
    `mEnd` - `plant2` agreeing bytes between `ip+len1` and `mStart`. A
    difference is forced at the end of each planted run, so the first difference
    is inside the case's window and the count is well defined."""
    for addr in range(IP_BASE, IP_BASE + n + PAD):
        mem[addr] = rng.randrange(256)
    for addr in range(MATCH_BASE - dist, MATCH_BASE + tail + PAD):
        mem[addr] = rng.randrange(256)
    run1 = min(plant1, n, tail)
    for j in range(run1):
        mem[IP_BASE + j] = mem[MATCH_BASE + j]
    if run1 < min(n, tail):
        mem[IP_BASE + run1] = (mem[MATCH_BASE + run1] + 1) & 0xFF
    if run1 < tail or n < tail:
        return mem                      # phase 1 cannot reach mEnd
    len1 = tail
    for j in range(plant2):
        mem[IP_BASE + len1 + j] = mem[MATCH_BASE - dist + j]
    if plant2 < n - len1:
        mem[IP_BASE + len1 + plant2] = \
            (mem[MATCH_BASE - dist + plant2] + 1) & 0xFF
    return mem


def _make(rng, n, tail, dist, plant1, plant2):
    mem = plant({}, rng, n, tail, dist, plant1, plant2)
    return {"n": n, "tail": tail, "dist": dist, "plant1": plant1,
            "plant2": plant2, "mem": mem, "geometry": geometry(n, tail, dist)}


def _draw(rng, name):
    if name == "prefix":
        n = rng.randrange(1, 65)
        tail = rng.randrange(1, 65)
        return (n, tail, rng.randrange(max(8, n + 8), max(8, n + 8) + 64),
                rng.randrange(0, min(n, tail)), 0)
    if name == "wrap":
        tail = rng.randrange(1, 33)
        n = rng.randrange(tail + 1, tail + 65)
        return (n, tail, rng.randrange(max(8, n + 8), max(8, n + 8) + 64),
                tail, rng.randrange(0, n - tail))
    if name == "wrap_iend":
        tail = rng.randrange(0, 33)
        n = rng.randrange(tail + 1, tail + 65)
        return (n, tail, rng.randrange(max(8, n + 8), max(8, n + 8) + 64),
                tail, n - tail)
    if name == "empty_tail":
        n = rng.randrange(1, 65)
        return (n, 0, rng.randrange(max(8, n + 8), max(8, n + 8) + 64), 0,
                rng.randrange(0, n + 1))
    n = rng.randrange(1, 33)
    tail = rng.randrange(n, n + 65)
    return (n, tail, rng.randrange(max(8, n + 8), max(8, n + 8) + 64), n, 0)


def generate_cases(seed=115):
    """The full sweep: 2400 cases, 480 per family, the boundaries first."""
    import random
    rng = random.Random(seed)
    out = []
    for name in FAMILIES:
        rows = [{"family": name, **dict(zip(
            ("n", "tail", "dist", "plant1", "plant2"), vals))}
            for vals in BOUNDARY_CASES[name]]
        while len(rows) < 480:
            n, tail, dist, p1, p2 = _draw(rng, name)
            rows.append({"family": name, "n": n, "tail": tail, "dist": dist,
                         "plant1": p1, "plant2": p2})
        assert len(rows) == 480, (name, len(rows))
        out.extend(rows)
    assert len(out) == 2400, len(out)
    return out


LEDGER_PER_FAMILY = 60


def _stride(seq, need):
    assert need <= len(seq), (need, len(seq))
    if need == len(seq):
        return list(seq)
    step = len(seq) / need
    return [seq[int(i * step)] for i in range(need)]


def _case(case, seed=115):
    """Build the memory for a plain case description, deterministically."""
    import random
    rng = random.Random((seed + 7 * case["n"] + 13 * case["tail"]
                         + 17 * case["dist"] + 19 * case["plant1"]
                         + 23 * case["plant2"]) & 0xFFFFFFFF)
    return _make(rng, case["n"], case["tail"], case["dist"], case["plant1"],
                 case["plant2"])


def _answer(case):
    built = _case(case)
    return count_2segments(built["mem"], built["geometry"])


def ledger_rows(rows=None):
    """A 300-case stratified, reviewable subset: every family's boundary rows
    are kept verbatim and the rest of the family is strided."""
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
        r = {k: r[k] for k in ("family", "n", "tail", "dist", "plant1",
                               "plant2")}
        r["id"] = i + 1
        total, len1, len2, reached = _answer(r)
        r["len1"] = len1
        r["len2"] = len2
        r["expected"] = total
        r["wrapped"] = 1 if reached else 0
        out[i] = r
    return out


def replay_case(case):
    """Re-derive a committed row: model and decoded execution must agree."""
    built = _case(case)
    total, len1, len2, reached = count_2segments(built["mem"],
                                                 built["geometry"])
    got = count_2segments_decoded(built["mem"], built["geometry"])
    assert total == got, (case, total, got)
    assert (len1 + len2) == total, (case, len1, len2, total)
    if not reached:
        assert len2 == 0, (case, len2)
    return total


def cases_tsv_rows():
    rows = ["id\tfamily\tn\ttail_len\tmstart_dist\tphase1_len\tphase2_len"
            "\texpected\treached_mend"]
    for r in ledger_rows():
        rows.append("\t".join([
            str(r["id"]), r["family"], str(r["n"]), str(r["tail"]),
            str(r["dist"]), str(r["len1"]), str(r["len2"]),
            str(r["expected"]), str(r["wrapped"]),
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
