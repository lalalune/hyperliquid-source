#!/usr/bin/env python3
"""Reconstruct the node #115 legacy cache-local bloom filter probe path.

Four functions are rebuilt: the 32-bit string hash 0x61c34a0 (seed 0xbc9f1d34),
the single-key probe 0x612d930, the batched probe 0x612d7b0 (two passes: hash and
prefetch, then test) and the builder-side hash append with adjacent-duplicate
suppression 0x61365c0.  The tool reads constants and FDE extents from ELF bytes,
evaluates the real machine code with the concrete x86-64 evaluator of the merged
RE-021 admission tool extended by the few opcodes these bodies add (the binary is
never executed), and compares every case with an independent pure-Python model.
Negative controls show that wrong models and corrupted code bytes are detected.
"""
import argparse
import hashlib
import json
import pathlib
import random
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re21_tx_admission115 as base  # noqa: E402
from re21_tx_admission115 import ToolError, fail, M64  # noqa: E402

BINARY = base.BINARY
SHA256 = base.SHA256
HASH, SINGLE, MULTI, ADDKEY = 0x61c34a0, 0x612d930, 0x612d7b0, 0x61365c0
GROW = 0x5e7e440  # vector grow-and-insert callee of ADDKEY, replaced by a recorded stub
SEED = 0xbc9f1d34
MUL = 0xc6a4a793
M32 = 0xffffffff
CANARY = 0x1122334455667788
SELF_AT, DATA_AT, KEYS_AT, OUT_AT, HEAP_AT = 0x7d00_0000_0000, 0x7d00_1000_0000, 0x7d00_2000_0000, 0x7d00_3000_0000, 0x7d00_4000_0000
KEYS_SIZE = 0x8000
MAX_BATCH = 32  # stack hash/line arrays of 0x80 bytes each (0x10 and 0x90 in the frame)


# ---------------------------------------------------------------- evaluator
def _opcode_at(code):
    p = 0
    while code[p] in (0x66, 0x2e, 0x64, 0xf3):
        p += 1
    if 0x40 <= code[p] <= 0x4f:
        p += 1
    return p


def decode_ext(code, va):
    """Decode the forms these bodies add on top of the admission-tool subset."""
    if code[:4] == bytes.fromhex("f30f1efa"):
        return {"op": 0xfa1e, "rex": 0, "size": 32, "len": 4, "bytes": bytes(code[:4])}
    if code[0] == 0x64 and code[1:3] in (b"\x48\x8b", b"\x48\x2b") and code[3:9] == bytes.fromhex("04252800 0000".replace(" ", "")):
        return {"op": 0xf5 if code[2] == 0x8b else 0xf6, "rex": 0x48, "size": 64, "len": 9, "bytes": bytes(code[:9])}
    if code[0] == 0x48 and code[1] == 0x98:
        return {"op": 0x98, "rex": 0x48, "size": 64, "len": 2, "bytes": bytes(code[:2])}
    p = _opcode_at(code)
    op = code[p]
    fixed = None
    if op == 0xd3:
        fixed = bytes(code[:p]) + b"\xd1" + bytes(code[p + 1:])
    elif op == 0x69:
        fixed = bytes(code[:p]) + b"\x81" + bytes(code[p + 1:])
    elif op == 0x88:
        fixed = bytes(code[:p]) + b"\x89" + bytes(code[p + 1:])
    elif op == 0x0f and code[p + 1] in (0xbe, 0xa3, 0x18):
        fixed = bytes(code[:p]) + b"\x0f\xb6" + bytes(code[p + 2:])
    elif op == 0xf7 and (code[p + 1] >> 3) & 7 == 6:
        fixed = bytes(code[:p]) + b"\xf7" + bytes([(code[p + 1] & 0xc7) | 0x10]) + bytes(code[p + 2:])  # decode as not
    if fixed is None:
        return None
    form = base.decode(fixed, va)
    form["op"] = op if op != 0x0f else 0x0f00 | code[p + 1]
    if op == 0xf7:
        form["reg"] = 6
    form["bytes"] = bytes(code[:form["len"]])
    return form


class Machine(base.Machine):
    """Admission-tool evaluator plus signed flags, shifts by cl, div, bt, movsx, imul-imm and byte stores."""

    def __init__(self, image, code_override=None):
        self.grow_calls = []
        super().__init__(image, code_override)

    def fetch(self, va):
        form = self.cache.get(va)
        if form is None:
            code = bytearray(self.image.code(va, 16))
            for i in range(16):
                if va + i in self.override:
                    code[i] = self.override[va + i]
            form = decode_ext(bytes(code), va) or base.decode(bytes(code), va)
            self.cache[va] = form
        return form

    def flags_logic(self, res, size):
        res = super().flags_logic(res, size)
        self.of = False
        return res

    def flags_add(self, a, b, size):
        res = super().flags_add(a, b, size)
        sa, sb, sr = a >> (size - 1), b >> (size - 1), res >> (size - 1)
        self.of = sa == sb and sa != sr
        return res

    def flags_sub(self, a, b, size):
        res = super().flags_sub(a, b, size)
        sa, sb, sr = a >> (size - 1), b >> (size - 1), res >> (size - 1)
        self.of = sa != sb and sa != sr
        return res

    def cond(self, code, va):
        if code == 10 or code == 11:
            fail(f"parity condition at {va:#x}")
        if code >= 12:
            lt = self.sf != self.of
            return {12: lt, 13: not lt, 14: lt or self.zf, 15: not (lt or self.zf)}[code]
        return super().cond(code, va)

    def step(self, va):
        f = self.fetch(va)
        op, size, nxt = f["op"], f["size"], (va + f["len"]) & M64
        if op == 0xfa1e or op == 0x0f18:
            return nxt
        if op == 0xf5:
            self.regs[0] = CANARY
            return nxt
        if op == 0xf6:
            self.flags_sub(self.regs[0], CANARY, 64)
            self.regs[0] = (self.regs[0] - CANARY) & M64
            return nxt
        if op == 0x98:
            self.regs[0] = (self.regs[0] & M32) - (1 << 32) if self.regs[0] & 0x80000000 else self.regs[0] & M32
            self.regs[0] &= M64
            return nxt
        if op == 0xd3:
            count, kind = self.regs[1] & (63 if size == 64 else 31), f["reg"] & 7
            a, mask = self.get(f["rm"], size, f, va), (1 << size) - 1
            if kind == 4:
                res = (a << count) & mask
            elif kind == 5:
                res = a >> count
            else:
                fail(f"unsupported shift-by-cl form at {va:#x}")
            if count:
                self.flags_logic(res, size)
            self.put(f["rm"], size, res, f, va)
            return nxt
        if op == 0x69:
            mask = (1 << size) - 1
            b = self.get(f["rm"], size, f, va)
            self.set_reg(f["reg"], size, (b * (f["imm"] & mask)) & mask, f)
            self.of = None
            return nxt
        if op == 0x88:
            self.put(f["rm"], 8, self.reg(f["reg"], 8, f), f, va)
            return nxt
        if op == 0x0fbe:
            v = self.get(f["rm"], 8, f, va)
            self.set_reg(f["reg"], size, (v - 256 if v & 0x80 else v) & ((1 << size) - 1), f)
            return nxt
        if op == 0x0fa3:
            if f["rm"][0] != "r":
                fail("bt with a memory operand")
            self.cf = bool((self.get(f["rm"], size, f, va) >> (self.reg(f["reg"], size, f) % size)) & 1)
            return nxt
        if op == 0xf7 and f["reg"] == 6:
            d = self.get(f["rm"], size, f, va)
            if d == 0:
                fail("divide by zero")
            num = (self.regs[2] << size | self.regs[0] & ((1 << size) - 1)) & ((1 << 2 * size) - 1)
            q, r = divmod(num, d)
            if q >> size:
                fail("divide overflow")
            self.set_reg(0, size, q, f)
            self.set_reg(2, size, r, f)
            return nxt
        return super().step(va)


def new_machine(image, override=None):
    m = Machine(image, override)
    return m


def grow_stub(m):
    """Stand-in for the vector grow-and-insert callee: checks its arguments, appends the value."""
    vec, end, ptr = m.regs[7], m.regs[6], m.regs[2]
    begin, cur, cap = m.load(vec, 8), m.load(vec + 8, 8), m.load(vec + 16, 8)
    if cur != end:
        fail("grow stub: end argument differs from the vector end")
    count = (cur - begin) // 4
    value = m.load(ptr, 4)
    new_cap = max(1, 2 * count)
    new_begin = HEAP_AT + m.heap_next
    m.heap_next += 4 * new_cap + 16
    m.regions[-1][2][new_begin - HEAP_AT:new_begin - HEAP_AT + 4 * count] = b"".join(
        m.load(begin + 4 * i, 4).to_bytes(4, "little") for i in range(count))
    m.store(new_begin + 4 * count, 4, value)
    m.store(vec, 8, new_begin)
    m.store(vec + 8, 8, new_begin + 4 * (count + 1))
    m.store(vec + 16, 8, new_begin + 4 * new_cap)
    m.grow_calls.append((count, cap - begin >> 2, value))


class Image(base.Image):
    pass


# ---------------------------------------------------------------- reconstruction (pure Python)
def rol32(x, n):
    n &= 31
    return ((x << n) | (x >> (32 - n))) & M32 if n else x


def sext8(b):
    return b - 256 if b & 0x80 else b


def hash32(data, seed=SEED, mut=()):
    """Model of 0x61c34a0 (hash(data, len, seed))."""
    m = MUL - 1 if "mul" in mut else MUL
    n = len(data)
    h = (seed ^ (((n + 1) if "initlen" in mut else n) * m)) & M32
    i = 0
    limit = 5 if "word_lt5" in mut else 4
    while i + limit <= n:
        h = (h + int.from_bytes(data[i:i + 4], "little")) & M32
        h = (h * m) & M32
        h ^= h >> (15 if "shr15" in mut else 16)
        i += 4
    rem = n - i
    if rem == 0:
        return (h * 1 & M32) if "mix0" not in mut else (((h * m) & M32) ^ (((h * m) & M32) >> 24))
    ext = (lambda b: b) if "zext" in mut else sext8
    if rem == 3:
        h = (h + (ext(data[i + 2]) << 16)) & M32
    if rem >= 2:
        h = (h + (ext(data[i + 1]) << 8)) & M32
    h = (h + ext(data[i])) & M32
    h = (h * m) & M32
    return h ^ (h >> (23 if "shr23" in mut else 24))


def probe(data, off, num_probes, h, log2_line, mut=()):
    """Test num_probes bits of one cache line starting at byte offset off; h is the key hash."""
    delta = rol32(h, 14 if "rol14" in mut else (17 if "ror15" in mut else 15))
    bits = log2_line + (2 if "mask2" in mut else 4 if "mask4" in mut else 3)
    mask = ((1 << (bits & 31)) - 1) & M32
    count = num_probes - 1 if "probes-1" in mut else num_probes + 1 if "probes+1" in mut else num_probes
    if num_probes <= 0 and "neg_false" in mut:
        return False
    for _ in range(count):
        pos = h & mask
        byte = data[off + (pos >> 3)]
        bit = (byte >> (7 - (pos & 7))) & 1 if "msb" in mut else (byte >> (pos & 7)) & 1
        if not bit:
            return False
        h = (h + delta) & M32
    return True


def line_offset(h, num_lines, log2_line, mut=()):
    idx = (h & (num_lines - 1)) if "andlines" in mut else h % num_lines
    return (idx << (log2_line + 1 if "line+1" in mut else log2_line)) & M32


def single_may_match(data, num_probes, num_lines, log2_line, key, mut=()):
    """Model of 0x612d930: True iff every probe bit of the key's line is set."""
    h = hash32(key)
    return probe(data, line_offset(h, num_lines, log2_line, mut), num_probes, h, log2_line, mut)


def multi_may_match(data, num_probes, num_lines, log2_line, keys, mut=()):
    """Model of 0x612d7b0 over a batch of up to 32 keys."""
    hashes = [hash32(k) for k in keys]
    out = []
    for i, h in enumerate(hashes):
        use = hashes[(i + 1) % len(hashes)] if "next_key" in mut else h
        res = probe(data, line_offset(use, num_lines, log2_line, mut), num_probes, use, log2_line, mut)
        out.append(not res if "invert_last" in mut and i == len(hashes) - 1 else res)
    return out


def add_key(entries, cap, key, mut=()):
    """Model of 0x61365c0: hash-append with adjacent duplicate suppression.  Returns (entries, grew)."""
    h = hash32(key)
    if "nodedupe" in mut:
        dup = False
    elif "first" in mut:
        dup = bool(entries) and entries[0] == h
    elif "any" in mut:
        dup = h in entries
    else:
        dup = bool(entries) and entries[-1] == h
    if dup:
        return entries, False
    grew = len(entries) == (cap - 1 if "cap-1" in mut else cap)
    return entries + [h], grew


def set_bits(data, num_lines, log2_line, key, num_probes):
    """Builder-side insert implied by the probe geometry (used only to create matching inputs)."""
    h = hash32(key)
    off = line_offset(h, num_lines, log2_line)
    delta = rol32(h, 15)
    mask = (1 << (log2_line + 3)) - 1
    for _ in range(num_probes):
        pos = h & mask
        data[off + (pos >> 3)] |= 1 << (pos & 7)
        h = (h + delta) & M32


# ---------------------------------------------------------------- harness
class Harness:
    def __init__(self, image, override=None):
        self.image = image
        self.m = new_machine(image, override)
        self.m.stubs[GROW] = grow_stub

    def fresh(self, data_len=0):
        m = self.m
        m.reset()
        m.stubs[GROW] = grow_stub
        m.grow_calls = []
        m.heap_next = 0
        m.add_region(SELF_AT, 0x100)
        m.add_region(DATA_AT, max(data_len, 16))
        m.add_region(KEYS_AT, KEYS_SIZE)
        m.add_region(OUT_AT, 0x100)
        m.add_region(HEAP_AT, 0x20000)
        return m

    def call(self, start, rdi=0, rsi=0, rdx=0, rcx=0, limit=400000):
        m = self.m
        m.regs[7], m.regs[6], m.regs[2], m.regs[1] = rdi, rsi, rdx, rcx
        m.run(start, limit)
        return m.regs[0]

    @staticmethod
    def put_bytes(m, base_va, content):
        for lo, hi, buf in m.regions:
            if lo <= base_va < hi:
                buf[base_va - lo:base_va - lo + len(content)] = content
                return
        fail("harness write outside regions")

    def run_hash(self, data, seed):
        m = self.fresh()
        self.put_bytes(m, KEYS_AT, data)
        return self.call(HASH, KEYS_AT, len(data), seed) & M32, m.steps

    def setup_filter(self, data, num_probes, num_lines, log2_line):
        m = self.fresh(len(data))
        self.put_bytes(m, DATA_AT, data)
        self.put_bytes(m, SELF_AT + 8, struct.pack("<Q", DATA_AT))
        self.put_bytes(m, SELF_AT + 0x10, struct.pack("<iII", num_probes, num_lines, log2_line))
        return m

    def put_key(self, m, slot, key, at):
        self.put_bytes(m, KEYS_AT + at, key)
        self.put_bytes(m, KEYS_AT + 0x4000 + 16 * slot, struct.pack("<QQ", KEYS_AT + at, len(key)))
        return KEYS_AT + 0x4000 + 16 * slot

    def run_single(self, data, num_probes, num_lines, log2_line, key):
        m = self.setup_filter(data, num_probes, num_lines, log2_line)
        slice_at = self.put_key(m, 0, key, 0)
        return bool(self.call(SINGLE, SELF_AT, slice_at) & 0xff), m.steps

    def run_multi(self, data, num_probes, num_lines, log2_line, keys):
        m = self.setup_filter(data, num_probes, num_lines, log2_line)
        ptrs, at = b"", 0x100
        for i, key in enumerate(keys):
            ptrs += struct.pack("<Q", self.put_key(m, i, key, at))
            at += len(key) + 8
        self.put_bytes(m, KEYS_AT + 0x6000, ptrs)
        self.call(MULTI, SELF_AT, len(keys), KEYS_AT + 0x6000, OUT_AT)
        outs = [m.load(OUT_AT + i, 1) for i in range(len(keys))]
        return outs, m.steps

    def run_addkey(self, entries, cap, key):
        """entries: current u32 list in a vector of capacity cap (cap >= len)."""
        m = self.fresh()
        begin = HEAP_AT + 0x10000
        m.regions[-1][2][0x10000:0x10000 + 4 * cap] = b"".join(e.to_bytes(4, "little") for e in entries) + bytes(4 * (cap - len(entries)))
        m.heap_next = 0
        self.put_bytes(m, SELF_AT + 0x10, struct.pack("<QQQ", begin, begin + 4 * len(entries), begin + 4 * cap))
        slice_at = self.put_key(m, 0, key, 0)
        self.call(ADDKEY, SELF_AT, slice_at)
        b2, e2 = m.load(SELF_AT + 0x10, 8), m.load(SELF_AT + 0x18, 8)
        got = [m.load(b2 + 4 * i, 4) for i in range((e2 - b2) // 4)]
        return got, len(m.grow_calls), m.steps


# ---------------------------------------------------------------- static evidence
def function_rows(image):
    _, fdes = base.fde_extents.eh_frame_records(image.data, image.secs)
    starts = {f["start"]: f["end"] for f in fdes}
    rows = []
    for name, va in (("hash", HASH), ("single", SINGLE), ("multi", MULTI), ("addkey", ADDKEY)):
        if va not in starts:
            fail(f"no FDE starts at {va:#x}")
        rows.append((name, va, starts[va]))
    return rows


def static_rows(image, rows):
    out, targets = [], {}
    for name, start, end in rows:
        va = start
        while va < end:
            f = decode_ext(image.code(va, 16), va) or base.decode(image.code(va, 16), va)
            out.append(f"{name}\t{va:#x}\t{f['len']}\t{f['bytes'].hex()}\t{f['op']:#x}")
            if "target" in f and f["op"] == 0xe8:
                targets.setdefault(name, set()).add(f["target"])
            va += f["len"]
        if va != end:
            fail(f"linear decode overruns {end:#x}")
    return out, targets


# ---------------------------------------------------------------- cases
def rand_key(rng):
    n = rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 16, 17, 20, 24, 31, 40])
    return bytes(rng.randrange(256) if rng.random() < 0.6 else rng.choice([0, 0x7f, 0x80, 0xff]) for _ in range(n))


def geometry(rng):
    log2_line = rng.choice([5, 6, 6, 6, 7])
    num_lines = rng.choice([1, 2, 3, 5, 7, 8, 13, 31, 64, 101])
    probes = rng.choice([0, 1, 2, 3, 4, 6, 6, 8, 10, 16, 24])
    return probes, num_lines, log2_line


def make_filter(rng, probes, num_lines, log2_line, keys_in):
    data = bytearray(num_lines << log2_line)
    density = rng.choice([0.0, 0.15, 0.5, 0.85, 1.0])
    for i in range(len(data)):
        data[i] = 0xff if density == 1.0 else sum(1 << b for b in range(8) if rng.random() < density)
    for k in keys_in:
        set_bits(data, num_lines, log2_line, k, probes)
    return bytes(data)


def hash_cases(rng, count):
    for i in range(count):
        n = i % 42 if i < 42 * 20 else rng.randrange(0, 70)
        yield bytes(rng.randrange(256) for _ in range(n)), rng.choice([SEED, SEED, 0, 1, 0xffffffff, rng.randrange(1 << 32)])


def single_cases(rng, count):
    for _ in range(count):
        probes, num_lines, log2_line = geometry(rng)
        pool = [rand_key(rng) for _ in range(rng.randrange(1, 6))]
        data = make_filter(rng, probes, num_lines, log2_line, pool[:rng.randrange(0, len(pool) + 1)])
        yield data, probes, num_lines, log2_line, rng.choice(pool + [rand_key(rng)])


def multi_cases(rng, count):
    for _ in range(count):
        probes, num_lines, log2_line = geometry(rng)
        pool = [rand_key(rng) for _ in range(rng.randrange(1, 12))]
        data = make_filter(rng, probes, num_lines, log2_line, pool[:rng.randrange(0, len(pool) + 1)])
        n = rng.randrange(1, MAX_BATCH + 1)
        yield data, probes, num_lines, log2_line, [rng.choice(pool + [rand_key(rng)]) for _ in range(n)]


def addkey_cases(rng, count):
    for _ in range(count):
        keys = [rand_key(rng) for _ in range(4)]
        length = rng.randrange(0, 5)
        entries = [hash32(rng.choice(keys)) for _ in range(length)]
        cap = length + rng.choice([0, 0, 1, 1, 2, 5])
        yield entries, cap, rng.choice(keys)


def evaluate(image, override=None, mut=(), counts=(1800, 3600, 2400, 2400), stop_on_first=False, sample=None):
    """Run every case; return summary counters and TSV lines for the first `sample` cases of each group."""
    hn = Harness(image, override)
    rng = random.Random(115)
    res = {"cases": 0, "mismatches": 0, "tool_errors": 0, "steps": {}, "grow_calls": 0, "dups": 0, "true": 0, "false": 0}
    lines = {"hash": [], "single": [], "multi": [], "addkey": []}
    kinds = (("hash", counts[0]), ("single", counts[1]), ("multi", counts[2]), ("addkey", counts[3]))

    def record(kind, ok, steps, line):
        res["cases"] += 1
        res["steps"][kind] = res["steps"].get(kind, 0) + steps
        if not ok:
            res["mismatches"] += 1
        if sample is not None and len(lines[kind]) < sample:
            lines[kind].append(line)
        return ok

    for kind, count in kinds:
        for case in {"hash": hash_cases, "single": single_cases, "multi": multi_cases, "addkey": addkey_cases}[kind](rng, count):
            try:
                if kind == "hash":
                    data, seed = case
                    got, steps = hn.run_hash(data, seed)
                    exp = hash32(data, seed, mut)
                    line = f"{len(data)}\t{data.hex()}\t{seed:#x}\t{exp:#x}\t{got:#x}\t{steps}"
                    ok = got == exp
                elif kind == "single":
                    data, probes, num_lines, log2_line, key = case
                    got, steps = hn.run_single(data, probes, num_lines, log2_line, key)
                    exp = single_may_match(data, probes, num_lines, log2_line, key, mut)
                    res["true" if exp else "false"] += 1
                    line = f"{probes}\t{num_lines}\t{log2_line}\t{hashlib.sha256(data).hexdigest()[:12]}\t{key.hex()}\t{int(exp)}\t{int(got)}\t{steps}"
                    ok = got == exp
                elif kind == "multi":
                    data, probes, num_lines, log2_line, keys = case
                    got, steps = hn.run_multi(data, probes, num_lines, log2_line, keys)
                    exp = [int(x) for x in multi_may_match(data, probes, num_lines, log2_line, keys, mut)]
                    res["true"] += sum(exp)
                    res["false"] += len(exp) - sum(exp)
                    line = f"{probes}\t{num_lines}\t{log2_line}\t{len(keys)}\t{''.join(map(str, exp))}\t{''.join(map(str, got))}\t{steps}"
                    ok = got == exp
                else:
                    entries, cap, key = case
                    got, grows, steps = hn.run_addkey(entries, cap, key)
                    exp, grew = add_key(entries, cap, key, mut)
                    res["grow_calls"] += grows
                    res["dups"] += int(len(exp) == len(entries))
                    line = f"{len(entries)}\t{cap}\t{key.hex()}\t{len(exp)}\t{len(got)}\t{grows}\t{int(grew)}\t{steps}"
                    ok = got == exp and grows == int(grew)
            except (ToolError, base.Boundary, IndexError):
                res["tool_errors"] += 1
                res["cases"] += 1
                res["mismatches"] += 1
                if stop_on_first:
                    return res, lines
                continue
            record(kind, ok, steps, line)
            if not ok and stop_on_first:
                return res, lines
    return res, lines


def battery(image, override=None, mut=()):
    """A small fixed battery used by the negative controls; True when the model and code disagree."""
    res, _ = evaluate(image, override, mut, counts=(120, 160, 60, 80), stop_on_first=True)
    return res["mismatches"] > 0


def find(image, start, end, pattern, which=0):
    body = image.code(start, end - start)
    at = -1
    for _ in range(which + 1):
        at = body.find(pattern, at + 1)
        if at < 0:
            fail(f"pattern {pattern.hex()} missing in {start:#x}")
    return start + at


def byte_controls(image, rows):
    ext = {name: (s, e) for name, s, e in rows}
    h, s, m, a = ext["hash"], ext["single"], ext["multi"], ext["addkey"]
    spec = [
        ("hash: first multiplier low byte", find(image, *h, bytes.fromhex("69c693a7a4c6")) + 2, 0xa6),
        ("hash: word-step shift 16 -> 17", find(image, *h, bytes.fromhex("c1e810")) + 2, 0x11),
        ("hash: tail shift 24 -> 23", find(image, *h, bytes.fromhex("c1e818")) + 2, 0x17),
        ("hash: tail byte 2 shift 16 -> 15", find(image, *h, bytes.fromhex("c1e210")) + 2, 0x0f),
        ("hash: tail byte 1 shift 8 -> 7", find(image, *h, bytes.fromhex("c1e208")) + 2, 0x07),
        ("hash: last tail sign-extend -> zero-extend", find(image, *h, bytes.fromhex("0fbe17")) + 1, 0xb6),
        ("hash: word loop jae -> jb", find(image, *h, bytes.fromhex("73e7")), 0x72),
        ("hash: word add -> sub", find(image, *h, bytes.fromhex("0342fc")), 0x2b),
        ("single: rotate 15 -> 14", find(image, *s, bytes.fromhex("41c1c20f")) + 3, 0x0e),
        ("single: mask shift base +3 -> +4", find(image, *s, bytes.fromhex("83c103")) + 2, 0x04),
        ("single: bt jae -> jb", find(image, *s, bytes.fromhex("0fa3c273")) + 3, 0x72),
        ("single: probe divisor field 0x14 -> 0x10", find(image, *s, bytes.fromhex("f77314")) + 2, 0x10),
        ("single: log2 field 0x18 -> 0x10", find(image, *s, bytes.fromhex("8b4b18")) + 2, 0x10),
        ("single: probe loop bound jle -> jg", find(image, *s, bytes.fromhex("4585c9")) + 3, 0x7f),
        ("single: bit index mask 7 -> 6", find(image, *s, bytes.fromhex("83e007")) + 2, 0x06),
        ("single: byte index shift 3 -> 2", find(image, *s, bytes.fromhex("c1ea03")) + 2, 0x02),
        ("single: seed immediate low byte", find(image, *s, bytes.fromhex("ba341d9fbc")) + 1, 0x35),
        ("multi: rotate 15 -> 14", find(image, *m, bytes.fromhex("41c1c30f")) + 3, 0x0e),
        ("multi: mask shift base +3 -> +4", find(image, *m, bytes.fromhex("83c103")) + 2, 0x04),
        ("multi: output store index register", find(image, *m, bytes.fromhex("880421")) + 2, 0x22),
        ("multi: bt jae -> jb", find(image, *m, bytes.fromhex("0fa3c273")) + 3, 0x72),
        ("multi: probe divisor field 0x14 -> 0x10", find(image, *m, bytes.fromhex("f7742414")) + 2, 0x10),
        ("addkey: tail compare displacement -4 -> -8", find(image, *a, bytes.fromhex("3946fc")) + 2, 0xf8),
        ("addkey: store advance 4 -> 8", find(image, *a, bytes.fromhex("4883c604")) + 3, 0x08),
        ("addkey: capacity field 0x20 -> 0x18", find(image, *a, bytes.fromhex("3b7320")) + 2, 0x18),
    ]
    return spec


def mutant_names():
    return [
        ("hash model: multiplier -1", ("mul",)), ("hash model: initial fold uses n+1", ("initlen",)),
        ("hash model: word shift 15", ("shr15",)), ("hash model: tail shift 23", ("shr23",)),
        ("hash model: tail zero-extend", ("zext",)), ("hash model: mix applied to aligned lengths", ("mix0",)),
        ("hash model: words need 5 bytes", ("word_lt5",)),
        ("probe model: rotate 14", ("rol14",)), ("probe model: rotate right 15", ("ror15",)),
        ("probe model: mask bits +2", ("mask2",)), ("probe model: mask bits +4", ("mask4",)),
        ("probe model: line shift +1", ("line+1",)), ("probe model: one probe fewer", ("probes-1",)),
        ("probe model: one probe more", ("probes+1",)), ("probe model: lines masked not divided", ("andlines",)),
        ("probe model: bit order msb first", ("msb",)), ("probe model: zero probes rejected", ("neg_false",)),
        ("multi model: next key hashed", ("next_key",)), ("multi model: last answer inverted", ("invert_last",)),
        ("addkey model: no suppression", ("nodedupe",)), ("addkey model: compares first entry", ("first",)),
        ("addkey model: suppresses any earlier entry", ("any",)), ("addkey model: grows one early", ("cap-1",)),
    ]


def negative_controls(image, rows):
    out = []
    for name, mut in mutant_names():
        out.append((name, battery(image, None, mut)))
    for name, va, new in byte_controls(image, rows):
        out.append((f"code byte {va:#x}: {name}", battery(image, {va: new})))
    # out-of-range and damaged-input controls
    try:
        Image(image.data[:-1] + bytes([image.data[-1] ^ 1]))
        out.append(("input binary last byte flipped", False))
    except ToolError:
        out.append(("input binary last byte flipped", True))
    for name, va in (("start inside the hash body", HASH + 4), ("address in .rodata", 0x600000), ("address 0", 0)):
        try:
            if va not in {s for _, s, _ in rows}:
                fail("not an FDE start")
            out.append((f"FDE lookup: {name}", False))
        except ToolError:
            out.append((f"FDE lookup: {name}", True))
    hn = Harness(image)
    m = hn.setup_filter(bytes(64), 6, 0, 6)
    slice_at = hn.put_key(m, 0, b"x", 0)
    try:
        hn.call(SINGLE, SELF_AT, slice_at)
        out.append(("filter with zero lines (divide by zero)", False))
    except ToolError:
        out.append(("filter with zero lines (divide by zero)", True))
    try:
        hn2 = Harness(image)
        m = hn2.setup_filter(bytes(16), 6, 8, 6)
        hn2.call(SINGLE, SELF_AT, hn2.put_key(m, 0, b"x", 0))
        out.append(("filter data shorter than lines (read outside region)", False))
    except ToolError:
        out.append(("filter data shorter than lines (read outside region)", True))
    return out


def generate(out):
    data = BINARY.read_bytes()
    image = Image(data)
    rows = function_rows(image)
    listing, targets = static_rows(image, rows)
    for name in ("single", "multi", "addkey"):
        if HASH not in targets.get(name, set()):
            fail(f"{name} does not call the hash entry")
    if GROW not in targets["addkey"]:
        fail("addkey does not call the grow callee")
    res, lines = evaluate(image, sample=240)
    controls = negative_controls(image, rows)
    detected = sum(1 for _, d in controls if d)
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    summary = {
        "binary": "artifacts/node/115/hl-node", "binary_sha256": SHA256,
        "functions": {n: {"fde_start": f"{s:#x}", "fde_end": f"{e:#x}", "bytes": e - s,
                          "sha256_of_bytes": hashlib.sha256(image.code(s, e - s)).hexdigest()} for n, s, e in rows},
        "calls": {n: sorted(f"{t:#x}" for t in v) for n, v in sorted(targets.items())},
        "cases": res["cases"], "mismatches": res["mismatches"], "tool_errors": res["tool_errors"],
        "probe_true": res["true"], "probe_false": res["false"],
        "addkey_grow_calls": res["grow_calls"], "addkey_suppressed": res["dups"],
        "executed_steps": {k: res["steps"][k] for k in sorted(res["steps"])},
        "negative_controls": len(controls), "negative_detected": detected,
    }
    measure = {"cases": res["cases"] - res["mismatches"], "negative_controls": len(controls), "negative_detected": detected}
    files = {
        "summary.json": json.dumps(summary, indent=2, sort_keys=True) + "\n",
        "measure.json": json.dumps(measure, indent=2, sort_keys=True) + "\n",
        "decoded-instructions.tsv": "function\tva\tlength\tbytes\topcode_key\n" + "\n".join(listing) + "\n",
        "hash-cases.tsv": "length\tdata\tseed\texpected\tgot\tsteps\n" + "\n".join(lines["hash"]) + "\n",
        "single-cases.tsv": "probes\tlines\tlog2_line\tfilter_sha12\tkey\texpected\tgot\tsteps\n" + "\n".join(lines["single"]) + "\n",
        "multi-cases.tsv": "probes\tlines\tlog2_line\tkeys\texpected\tgot\tsteps\n" + "\n".join(lines["multi"]) + "\n",
        "addkey-cases.tsv": "entries\tcap\tkey\texpected_len\tgot_len\tgrow_calls\texpected_grow\tsteps\n" + "\n".join(lines["addkey"]) + "\n",
        "negative-controls.tsv": "control\tverdict\n" + "\n".join(f"{n}\t{'detected' if d else 'MISSED'}" for n, d in controls) + "\n",
    }
    for name, text in files.items():
        (out / name).write_text(text, encoding="ascii", newline="\n")
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        summary = generate(args.out)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    bad = summary["mismatches"] + summary["negative_controls"] - summary["negative_detected"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
