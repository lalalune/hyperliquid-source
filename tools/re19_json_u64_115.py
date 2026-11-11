#!/usr/bin/env python3
"""Reconstruct and validate the node #115 serde_json unsigned-integer reader 0x3ef2dc0 and its digit parser 0x3ef2440.

0x3ef2dc0(de) skips JSON whitespace, then dispatches on the next byte: '-' consumes it and parses a negative number,
an ASCII digit parses a positive number, anything else asks the type-mismatch helper 0x3ef2ab0 for an error.  The number
itself comes from 0x3ef2440(out, de, positive), which reads one digit run into a u64 accumulator (overflow past
18446744073709551615 and every fraction/exponent tail are delegated to boundaries), rejects a leading zero followed by a
digit, and returns a ParserNumber-like pair (tag 0 float, 1 unsigned, 2 signed, 3 error).  The reader maps that pair to
Ok(u64) or one of three error constructors.  All code bytes, constants, vtable targets and relocations are read from the
ELF file; the real machine code is evaluated by the concrete x86-64 evaluator of the merged materializer tool with the
callees stubbed at their call interface, and every case is compared with the pure-Python model below, including the
ordered call trace.  The binary is never executed.  Names (reader, number parser, error constructors) are inferences
from the code shape, not from strings.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re16_state_materialize115 as mat  # noqa: E402

BINARY = mat.BINARY
SHA256 = mat.SHA256
ToolError = mat.ToolError
fail = mat.fail
M64 = mat.M64

READER = 0x3ef2dc0       # deserialize an unsigned integer
NUMBER = 0x3ef2440       # parse one integer / start of a number
NUMBER_TAIL = 0x3ef20f0  # fraction / exponent / finishing boundary (stub)
ERR_AT = 0x3ef1a90       # error constructor at the current index
ERR_PEEK = 0x3ef3450     # error constructor at the unclamped index
MISMATCH = 0x3ef2ab0     # peek-and-report-type-mismatch (stub)
FIX_POS = 0x4671240      # attach a position to an error that has none
SLOT_UNSIGNED = 0x64e0900
SLOT_SIGNED = 0x64e0910
SLOT_LONG = 0x64e1340
SLOT_PANIC = 0x64df520
SLOT_MAKE = 0x64e0b08    # builds the final error from (code pointer, position)
SLOT_FREE = 0x64df4a0    # releases the position-less error object
POSITION = 0x5c56920     # position helper (stub)
ARENA_AT = 0x7a30_0000_0000

DE_AT = 0x7a00_0000_0000
DATA_AT = 0x7a10_0000_0000
OUT_AT = 0x7a20_0000_0000
JUNK = 0xdead_beef_0bad_f00d
SAVED = (0x1111111111111111, 0x2222222222222222, 0x3333333333333333, 0x4444444444444444, 0x5555555555555555,
         0x6666666666666666)
SAVED_REGS = (3, 5, 12, 13, 14, 15)
GUARD = 0x5a
CASES = 12000
SAMPLE = 1200
WS = (0x20, 0x09, 0x0a, 0x0d)
NEAR = (b"1844674407370955160", b"1844674407370955161", b"1844674407370955162", b"18446744073709551615",
        b"18446744073709551616", b"184467440737095516150", b"184467440737095516159", b"9223372036854775807",
        b"9223372036854775808", b"99999999999999999999", b"18446744073709551619", b"10000000000000000000")


# ---------------------------------------------------------------- static facts from the ELF bytes
def rip_target(image, va, disp_at, length):
    disp = struct.unpack("<i", image.code(disp_at, 4))[0]
    return (va + length + disp) & M64


def constants(image):
    mask = struct.unpack("<Q", image.code(READER + 0x21, 8))[0]
    limit = struct.unpack("<Q", image.code(NUMBER + 0x74, 8))[0]
    consts = {
        "whitespace_mask": mask,
        "whitespace_bytes": [b for b in range(64) if mask >> b & 1],
        "accumulator_limit_before_last_digit": limit,
        "accumulator_limit_equal": limit + 1,
        "last_digit_max_at_equal": image.code(NUMBER + 0xe2, 1)[0],
        "vtable_float": rip_target(image, 0x3ef2ec9, 0x3ef2ecc, 7),
        "vtable_peek": rip_target(image, 0x3ef2eee, 0x3ef2ef1, 7),
        "vtable_signed": rip_target(image, 0x3ef2f1f, 0x3ef2f22, 7),
        "eof_code": image.code(READER + 0x5a, 1)[0],
        "bad_digit_code": image.code(NUMBER + 0x173, 1)[0],
        "leading_zero_code": image.code(NUMBER + 0x4b, 1)[0],
        "decoder_index_offset": image.code(0x3ef345a, 1)[0],
        "decoder_length_offset": image.code(0x3ef3462, 1)[0],
        "error_line_offset": image.code(0x467124a, 1)[0],
        "error_object_size": image.code(0x467125d, 1)[0],
        "number_eof_code": image.code(NUMBER + 0x12d, 1)[0],
        "panic_slot_target": image.relative[SLOT_PANIC],
    }
    for name, slot in (("slot_unsigned", SLOT_UNSIGNED), ("slot_signed", SLOT_SIGNED), ("slot_long", SLOT_LONG)):
        consts[name + "_target"] = image.relative[slot]
    return consts


# ---------------------------------------------------------------- environment shared by model and machine stubs
class Env:
    """Deterministic callee results; both the model and the stubs call it, so the traces are directly comparable.

    Error objects are 0x28-byte records handed out from an arena: word 0 holds the error code, word 3 the line
    (zero means "no position yet").  The real error-constructor code reads these words.
    """

    def __init__(self, case):
        self.case = case
        self.trace = []
        self.objs = {}
        self.n = 0
        self.size = len(case["data"])

    def new(self, code, line):
        ptr = ARENA_AT + 0x40 * self.n
        self.n += 1
        self.objs[ptr] = (code & M64, line)
        return ptr

    def pos(self, ptr, length, limit):
        self.trace.append(("pos", ptr, length, limit))
        return 0x5000_0000_0000 | limit

    def make(self, code, pos):
        self.trace.append(("make", code, pos))
        return self.new(code, (pos & 0xffff) + 1)

    def free(self, ptr, size, align):
        self.trace.append(("free", ptr, size, align))

    def err(self, kind, code, idx):
        """Model of 0x3ef1a90 ("at": clamps idx + 1 to the length) and 0x3ef3450 ("peek": uses idx as is)."""
        limit = min(idx + 1, self.size) if kind == "at" else idx
        return self.make(code, self.pos(DATA_AT, self.size, limit))

    def fix(self, err, idx):
        """Model of 0x4671240: an error without a line gets one through 0x3ef3450, then the old object is freed."""
        if err not in self.objs:  # only reachable by a deliberately wrong model
            return err ^ 1
        code, line = self.objs[err]
        if line:
            return err
        new = self.err("peek", code, idx)
        self.free(err, 0x28, 0)
        return new

    def number(self, positive, sig, idx):
        self.trace.append(("number", positive, sig, idx))
        return self.case["pn"]

    def long(self, positive, sig, idx):
        self.trace.append(("long", positive, sig, idx))
        return self.case["long"]

    def peek(self, vtable, idx):
        self.trace.append(("peek", vtable, idx))
        return self.new(vtable, 0)

    def unexpected(self, slot, tag, payload, vtable):
        self.trace.append(("unexpected", slot, tag, payload, vtable))
        return self.new(slot << 8 | tag ^ payload << 16, 0)


# ---------------------------------------------------------------- the reconstruction
def model_number(env, data, idx, positive, k, mut=frozenset()):
    """0x3ef2440: returns (tag, value, idx)."""
    n = len(data)
    if idx >= n:
        code = k["number_eof_code"] + (1 if "eof_code" in mut else 0)
        return 3, env.err("peek", code, idx + (1 if "b_eof_idx_plus" in mut else 0)), idx
    first = data[idx]
    idx += 1
    digit = (lambda b: 0x30 <= b <= 0x39) if "digit_wide" not in mut else (lambda b: 0x30 <= b <= 0x3a)
    first_zero = 0x31 if "zero_is_31" in mut else 0x30
    if first == first_zero:
        if idx < n and digit(data[idx]):
            code = k["leading_zero_code"] - (1 if "leading_zero_code" in mut else 0)
            if "zero_digit_ok" in mut:
                return env.number(positive, 0, idx) + (idx,)
            return 3, env.err("at", code, idx), idx
        sig = 1 if "zero_sig" in mut else 0
        tag, val = env.number(positive ^ (1 if "positive_inverted" in mut else 0), sig, idx)
        return tag, val, idx
    if not 0x31 <= first <= 0x39:
        kind = "at" if "b_bad_at" in mut else "peek"
        return 3, env.err(kind, k["bad_digit_code"], idx), idx
    sig = 0 if "first_digit_lost" in mut else first - 0x30
    limit = k["accumulator_limit_before_last_digit"] + (1 if "limit_plus" in mut else 0)
    while True:
        if idx >= n or not digit(data[idx]):
            break
        d = data[idx] - 0x30
        low = sig < limit if "limit_strict" in mut else sig <= limit
        last = d <= k["last_digit_max_at_equal"] + (1 if "last_plus" in mut else 0) - (2 if "last_minus" in mut else 0)
        if low or (sig == limit + 1 and last):
            idx += 1 + (1 if "idx_skew" in mut else 0)
            sig = sig * 10 + d
            if sig > M64:
                if not mut:
                    raise ToolError("unreachable accumulator carry reached")
                sig &= M64
            continue
        flag, val = env.long(positive, sig, idx)
        if (flag == 0) != ("long_inverted" in mut):
            return (1 if "float_tag1" in mut else 0), val, idx
        return 3, val, idx
    tag, val = env.number(positive, sig + (1 if "sig_plus" in mut else 0), idx)
    return tag, val, idx


def model_reader(env, data, idx, k, mut=frozenset()):
    """0x3ef2dc0: returns (rax, rdx, idx)."""
    n = len(data)
    mask = k["whitespace_mask"] | (1 << 0x0b if "mask_vt" in mut else 0)
    if "mask_no_tab" in mut:
        mask &= ~(1 << 9)
    pos = idx
    while True:
        if pos >= n:
            code = k["eof_code"] + (1 if "reader_eof_code" in mut else 0)
            return 1, env.err("at", code, idx), idx
        b = data[pos]
        if b <= 0x2d and mask >> b & 1:
            pos += 1
            idx = pos
            continue
        break
    if b == 0x2d and "minus_other" not in mut:
        if "minus_kept" not in mut:
            idx = pos + 1
        tag, val, idx = model_number(env, data, idx, 0, k, mut)
        positive_path = False
    elif 0x30 <= b <= 0x39 or ("digit_wide_reader" in mut and b == 0x3a):
        tag, val, idx = model_number(env, data, idx, 1 if "positive_zero" not in mut else 0, k, mut)
        positive_path = True
    else:
        err = env.peek(k["vtable_peek"] + (8 if "vtable_peek" in mut else 0), idx)
        if "skip_fix" in mut:
            return 1, err, idx
        return 1, env.fix(err, idx), idx
    if tag == 3:
        if "fix_on_error" in mut:
            return 1, env.fix(val, idx), idx
        return 1, val, idx
    unsigned_ok = tag == 1 if "tag_swap" not in mut else tag == 2
    if tag == 2 and "neg_never_err" in mut:
        return 0, val, idx
    if unsigned_ok or (tag == 2 and not val >> 63 and "neg_always_err" not in mut):
        return 0, val, idx
    if tag == 2:
        slot = SLOT_SIGNED if "float_slot_signed" not in mut else SLOT_UNSIGNED
        err = env.unexpected(slot, 2, val, k["vtable_signed"])
    else:
        slot = SLOT_UNSIGNED if "float_slot_signed" not in mut else SLOT_SIGNED
        err = env.unexpected(slot, 3, val, k["vtable_float"])
    del positive_path
    if "no_fix_after_unexpected" in mut:
        return 1, err, idx
    return 1, env.fix(err, idx), idx


# ---------------------------------------------------------------- machine harness
def clobber(mm, ret):
    for r in (1, 2, 6, 7, 8, 9, 10, 11):
        mm.regs[r] = JUNK
    mm.regs[0] = ret
    mm.xmm = [JUNK | JUNK << 64] * 16


def install(m, env, k):
    img = m.image
    de_idx = lambda mm: mm.load(DE_AT + 0x28, 8)  # noqa: E731

    def sync(mm, ptr):
        code, line = env.objs[ptr]
        mm.store(ptr, 8, code)
        mm.store(ptr + 0x18, 8, line)
        return ptr

    def position(mm):
        clobber(mm, env.pos(mm.regs[7], mm.regs[6], mm.regs[2]))

    def make(mm):
        clobber(mm, sync(mm, env.make(mm.load(mm.regs[7], 8), mm.regs[6])))

    def free(mm):
        env.free(mm.regs[7], mm.regs[6], mm.regs[2] & 0xffffffff)
        clobber(mm, 0)

    def number(mm):
        out = mm.regs[7]
        if mm.regs[6] != DE_AT:
            fail("number tail called without the decoder")
        tag, val = env.number(mm.regs[2] & 0xffffffff, mm.regs[1], de_idx(mm))
        mm.store(out, 8, tag)
        mm.store(out + 8, 8, val)
        clobber(mm, out)

    def long_slot(mm):
        out = mm.regs[7]
        flag, val = env.long(mm.regs[2] & 0xffffffff, mm.regs[1], de_idx(mm))
        mm.store(out, 1, flag)
        mm.store(out + 8, 8, val)
        clobber(mm, out)

    def mismatch(mm):
        clobber(mm, sync(mm, env.peek(mm.regs[2], de_idx(mm))))

    def unexpected(slot):
        def f(mm):
            at = mm.regs[7]
            clobber(mm, sync(mm, env.unexpected(slot, mm.load(at, 1), mm.load(at + 8, 8), mm.regs[2])))
        return f

    m.stubs[NUMBER_TAIL] = number
    m.stubs[MISMATCH] = mismatch
    m.stubs[POSITION] = position
    m.stubs[img.relative[SLOT_MAKE]] = make
    m.stubs[img.relative[SLOT_FREE]] = free
    for slot, fn in ((SLOT_UNSIGNED, unexpected(SLOT_UNSIGNED)), (SLOT_SIGNED, unexpected(SLOT_SIGNED)),
                     (SLOT_LONG, long_slot)):
        m.stubs[img.relative[slot]] = fn
    m.stubs[img.relative[SLOT_PANIC]] = "panic"


def setup(m, case):
    m.reset()
    env = Env(case)
    install(m, env, constants_cache[0])
    data = case["data"]
    de = bytearray(0x60)
    struct.pack_into("<QQQ", de, 0x18, DATA_AT, len(data), case["idx"])
    m.add_region(DE_AT, 0x60, bytes(de))
    m.add_region(ARENA_AT, 0x40 * 64)
    m.add_region(DATA_AT, len(data) + 16, data + bytes([GUARD]) * 16)
    for r, v in zip(SAVED_REGS, SAVED):
        m.regs[r] = v
    return env


constants_cache = [None]


def finish(m, extra):
    de_idx = m.load(DE_AT + 0x28, 8)
    ok = [m.regs[r] for r in SAVED_REGS] == list(SAVED) and m.regs[4] == mat.STACK_TOP - 0x100
    return dict(extra, idx=de_idx, regs_ok=ok)


def run_reader(m, case):
    env = setup(m, case)
    m.regs[7] = DE_AT
    m.run(READER, limit=20000)
    return finish(m, {"rax": m.regs[0], "rdx": m.regs[2], "trace": env.trace})


def run_number(m, case):
    env = setup(m, case)
    m.add_region(OUT_AT, 0x40, bytes([0xcc]) * 0x40)
    m.regs[7], m.regs[6], m.regs[2] = OUT_AT, DE_AT, case["positive"] | JUNK << 8 & M64
    m.run(NUMBER, limit=20000)
    return finish(m, {"rax": m.regs[0], "tag": m.load(OUT_AT, 8), "val": m.load(OUT_AT + 8, 8), "trace": env.trace})


def expect(case, mut=frozenset()):
    k = constants_cache[0]
    env = Env(case)
    if case["entry"] == "reader":
        rax, rdx, idx = model_reader(env, case["data"], case["idx"], k, mut)
        return {"rax": rax, "rdx": rdx, "trace": env.trace, "idx": idx, "regs_ok": True}
    tag, val, idx = model_number(env, case["data"], case["idx"], case["positive"], k, mut)
    return {"rax": OUT_AT, "tag": tag, "val": val, "trace": env.trace, "idx": idx, "regs_ok": True}


def run_case(m, case):
    return run_reader(m, case) if case["entry"] == "reader" else run_number(m, case)


# ---------------------------------------------------------------- cases
class Rng:
    def __init__(self, seed):
        self.s = seed or 1

    def next(self):
        s = self.s
        s ^= s >> 12
        s ^= s << 25 & M64
        s ^= s >> 27
        self.s = s
        return s * 0x2545F4914F6CDD1D & M64

    def below(self, n):
        return self.next() % n

    def pick(self, seq):
        return seq[self.below(len(seq))]


def digits(rng, lo, hi):
    return bytes(0x30 + rng.below(10) for _ in range(lo + rng.below(hi - lo + 1)))


def token(rng, mode):
    ws = bytes(rng.pick(WS) for _ in range(rng.below(4)))
    if mode == 0:
        return ws + digits(rng, 1, 22) + bytes(rng.below(256) for _ in range(rng.below(3)))
    if mode == 1:
        return ws + b"-" + digits(rng, 1, 21) + bytes(rng.below(256) for _ in range(rng.below(2)))
    if mode == 2:
        edge = (0x2f, 0x3a, 0x2c, 0x2e, 0x2b, 0x0b, 0x0c, 0x08, 0x21, 0x40, 0x80, 0xff)
        return ws + bytes([rng.pick(edge) if rng.below(2) else rng.below(256)]) + digits(rng, 0, 4)
    if mode == 3:
        return ws
    if mode == 4:
        return ws + rng.pick(NEAR) + rng.pick((b"", b"0", b".5", b"e3", b" ", b"9"))
    if mode == 5:
        return ws + rng.pick((b"0", b"00", b"01", b"0.5", b"0e1", b"-0", b"-00", b"-01", b"0 ", b"09")) \
            + digits(rng, 0, 2)
    if mode == 6:
        return bytes(rng.below(256) for _ in range(rng.below(13)))
    if mode == 7:
        return ws + rng.pick((b"-", b"-x", b"- 1", b"--1", b"-+1", b"+1", b".5", b"e5", b"\x0b1", b"\x0c1", b"1"))
    return ws + digits(rng, 1, 3) + rng.pick((b"", b".", b"e", b"E+", b",", b"}", b"\xff", b":", b"/", b"\x00"))


def make_case(idx):
    rng = Rng(0x9e3779b97f4a7c15 ^ idx * 0x100000001b3 ^ 0x19)
    entry = "reader" if idx % 2 == 0 else "number"
    mode = (idx // 2) % 9
    body = token(rng, mode)
    prefix = bytes(rng.below(256) for _ in range(rng.below(3)))
    data = prefix + body
    start = len(prefix) if rng.below(8) else rng.below(len(data) + 1)
    if entry == "number" and start == len(prefix) and rng.below(8):
        while start < len(data) and data[start] in WS + (0x2d,):
            start += 1
    pn = (rng.below(4), rng.next() if rng.below(3) else rng.below(100))
    return {"id": idx, "entry": entry, "mode": mode, "data": data, "idx": start, "positive": rng.below(2),
            "pn": pn, "long": (rng.below(2), rng.next())}


def all_cases(count=CASES):
    for i in range(count):
        yield make_case(i)


def compare(want, got):
    return want == got


# ---------------------------------------------------------------- negative controls
MODEL_MUTANTS = (
    "mask_vt", "mask_no_tab", "eof_code", "reader_eof_code", "leading_zero_code", "limit_plus", "limit_strict",
    "last_plus", "last_minus", "minus_kept", "minus_other", "neg_always_err", "neg_never_err", "float_slot_signed",
    "skip_fix", "fix_on_error", "b_eof_idx_plus", "b_bad_at", "zero_digit_ok", "zero_sig", "positive_inverted",
    "first_digit_lost", "idx_skew", "long_inverted", "sig_plus", "vtable_peek", "tag_swap", "float_tag1",
    "no_fix_after_unexpected", "digit_wide", "zero_is_31", "positive_zero")
BYTE_MUTANTS = (
    (0x3ef24b4, 0x98, 0x99), (0x3ef2522, 0x05, 0x04), (0x3ef246b, 0x30, 0x31), (0x3ef247d, 0xd0, 0xd1),
    (0x3ef2df8, 0x2d, 0x2c), (0x3ef2de2, 0x26, 0x2e), (0x3ef2e1a, 0x05, 0x06), (0x3ef2e63, 0x03, 0x02),
    (0x3ef2ea4, 0x01, 0x00), (0x3ef2eaf, 0x78, 0x79), (0x3ef2e7d, 0x0a, 0x09), (0x3ef2e89, 0x01, 0x00),
    (0x3ef2518, 0x76, 0x72), (0x3ef24ab, 0x09, 0x08), (0x3ef2503, 0x74, 0x75), (0x3ef248b, 0x0d, 0x0c),
    (0x3ef2538, 0x74, 0x75), (0x3ef256d, 0x05, 0x06),
    (0x467124b, 0x00, 0x01), (0x467124c, 0x75, 0x74), (0x467125d, 0x28, 0x29), (0x3ef1a9f, 0x74, 0x75),
    (0x3ef1aa3, 0xc2, 0xca), (0x3ef1ab1, 0x43, 0x42), (0x3ef345a, 0x28, 0x20), (0x3ef3462, 0x20, 0x18))


def first_mismatch(m, cases, mut=frozenset()):
    for case in cases:
        try:
            got = run_case(m, case)
        except (ToolError, mat.Boundary) as exc:
            return case["id"], "error: " + str(exc)[:40]
        if got != expect(case, mut):
            return case["id"], "mismatch"
    return None, "clean"


def controls(image, cases):
    rows = []
    base = mat.Machine(image)
    for name in MODEL_MUTANTS:
        at, how = first_mismatch(base, cases, frozenset([name]))
        rows.append(("model-mutant", name, int(at is not None), at if at is not None else "-"))
    for va, old, new in BYTE_MUTANTS:
        if old == new:
            continue
        have = image.code(va, 1)[0]
        if have != old:
            raise ToolError(f"byte mutant at {va:#x} expects {old:#x}, file has {have:#x}")
        mm = mat.Machine(image, code_override={va: new})
        at, how = first_mismatch(mm, cases)
        rows.append(("byte-mutant", f"{va:#x}:{old:#04x}->{new:#04x}", int(at is not None), at if at is not None else "-"))
    bad = bytearray(image.data)
    bad[len(bad) // 2] ^= 1
    try:
        mat.Image(bytes(bad))
        found = 0
    except ToolError:
        found = 1
    rows.append(("input", "corrupted binary byte rejected by digest", found, "-"))
    try:
        image.code(image.text["address"] + image.text["size"], 4)
        found = 0
    except ToolError:
        found = 1
    rows.append(("input", "address past .text rejected", found, "-"))
    try:
        mm = mat.Machine(image)
        mm.add_region(DE_AT, 0x60, bytes(0x60))
        mm.regs[7] = DE_AT
        mm.run(0x3ef3000, limit=50)
        found = 0
    except (ToolError, mat.Boundary, KeyError, IndexError, struct.error):
        found = 1
    rows.append(("input", "start inside another function without its frame fails", found, "-"))
    return rows


# ---------------------------------------------------------------- generation
def generate(out):
    image = mat.Image(BINARY.read_bytes())
    k = constants(image)
    constants_cache[0] = k
    out.mkdir(parents=True, exist_ok=True)
    m = mat.Machine(image)
    digest = hashlib.sha256()
    bad = 0
    rows = ["case\tentry\tmode\tstart\tpositive\tinput_hex\tresult\tcalls\tfinal_idx\tmatch"]
    classes = {}
    cases = []
    for case in all_cases():
        got = run_case(m, case)
        want = expect(case)
        ok = compare(want, got)
        bad += not ok
        if case["entry"] == "reader":
            res = "ok" if want["rax"] == 0 else "err"
        else:
            res = f"tag{want['tag']}"
        key = f"{case['entry']}/{res}"
        classes[key] = classes.get(key, 0) + 1
        digest.update(repr((case["id"], got)).encode())
        if case["id"] < SAMPLE:
            rows.append(f"{case['id']}\t{case['entry']}\t{case['mode']}\t{case['idx']}\t{case['positive']}\t"
                        f"{case['data'].hex()}\t{res}\t{','.join(c[0] for c in got['trace'])}\t{got['idx']}\t"
                        f"{'yes' if ok else 'NO'}")
        if case["id"] < 2400:
            cases.append(case)
    (out / "cases.tsv").write_text("\n".join(rows) + "\n")
    (out / "outcome-classes.tsv").write_text(
        "class\tcases\n" + "".join(f"{key}\t{classes[key]}\n" for key in sorted(classes)))
    (out / "constants.json").write_text(json.dumps(k, indent=2, sort_keys=True) + "\n")
    ctl = controls(image, cases)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\tfirst_case\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    total = sum(classes.values())
    summary = {"binary_sha256": SHA256, "cases": total, "mismatches": bad, "outcome_digest": digest.hexdigest(),
               "negative_controls": len(ctl), "negative_detected": sum(r[2] for r in ctl)}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps(
        {"cases": total, "negative_controls": len(ctl), "negative_detected": sum(r[2] for r in ctl)},
        indent=2, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 1 if summary["mismatches"] or summary["negative_detected"] != summary["negative_controls"] else 0


if __name__ == "__main__":
    sys.exit(main())
