#!/usr/bin/env python3
"""Reconstruct and validate the node #115 state-load chain loader 0x3c12800 -> boundary 0x3c13520 -> builder 0x3c13610.

The chain is entered through the RELATIVE slot 0x64e7728 (one call site, 0x2b41f2d).  Observed contract:
  loader(rdi = A, rsi = B) -> Box<State> (0x42c8 bytes) or a panic.  A is a 4-word record {cap, ptr, w2, r15}; B is a
  6-word record whose words 0 and 1 are a (cap, ptr) buffer and whose tail at +0x18 has a drop glue 0x3932230.
  1. one-time-init gate: dword [0x64f01d8] != 0 runs the slow init through slot 0x64df9f0 (0x5c87d50) first;
  2. prep 0x4468c20 turns A into a 4-word record P; P0 == i64::MIN is the one rejected value (the `neg; jo` test);
  3. 0x38dbd80 produces a (cap, ptr, len) string N from the constant at 0x6476768;
  4. boundary 0x3c13520 (slot 0x64e9628) looks N up with 0x422e410: rax == 1 is the error arm (frees B's buffer, drops
     B+0x18, frees P's buffer, returns (1, error)); any other rax is the ok arm, which copies P (32 bytes) and B (48
     bytes) to its own frame and calls the builder through slot 0x64e73a0 with the looked-up 0x27a8-byte state;
  5. builder 0x3c13610 runs the materializer 0x3c2e860 (slot 0x64e9630; reconstructed by RE-016-state-materialize),
     allocates 0x42c8 bytes, copies the result into the allocation and frees the 0x27a8-byte input;
  6. the loader unwraps the boundary result (error arm: Result::unwrap panic), frees N when its cap is non-zero, checks
     box[0x28] == r15 (assert_eq), and patches the box: [0x10] = r15, [0x18] saturating +1, [0x20] = [0x30], [0x10e8] = 0,
     [0xdf0] = [0xef8] = [0x30], four 0xd88/0xed8/0x40c0 sub-object initialisers, [0x3e28] = [0x3ee0] = 0 (16 bit),
     [0x39b0] = 2; it frees A's buffer when its cap is non-zero and returns the box.
The tool evaluates the real machine code of all four functions (loader, boundary, builder, materializer) with the concrete
x86-64 evaluator of tools/re16_state_materialize115.py; only the imports, the allocator, the composer, the prep / name /
lookup / drop / sub-object helpers and the panic entries are stubs (the stubs scramble every caller-saved register).  Each
case is compared with the pure-Python `model()` including the exact symbolic call trace.  The binary is never executed.
Role names (prep, lookup, name) are inferences, not proven by any string.
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

BINARY, SHA256, M64 = mat.BINARY, mat.SHA256, mat.M64
ToolError, Boundary, fail = mat.ToolError, mat.Boundary, mat.fail

_decode = mat.decode


def decode16(code, va):
    """mat.decode plus the 66-prefixed `mov $imm16, r/m16` (c7 /0 iw)."""
    form = _decode(code, va)
    if form["op"] == 0xc7 and form["p66"]:
        at = form["len"] - 4
        form["imm"] = struct.unpack_from("<h", code, at)[0]
        form["len"] = at + 2
        form["bytes"] = bytes(code[:form["len"]])
    return form


mat.decode = decode16

LOADER, BOUNDARY, BUILDER, BODY = 0x3c12800, 0x3c13520, 0x3c13610, mat.BODY
SLOT_LOADER, SLOT_BOUNDARY, SLOT_BUILDER, SLOT_BODY = 0x64e7728, 0x64e9628, 0x64e73a0, mat.CTOR_SLOT
LOADER_CALL_SITE = 0x2b41f2d
PREP, NAME, LOOKUP, DROP = 0x4468c20, 0x38dbd80, 0x422e410, 0x3932230
FIX_A, FIX_B = 0x420b9c0, 0x420b900
SLOT_FIX_A2, SLOT_FIX_C = 0x64e4f08, 0x64e4f10
SLOT_DEALLOC, SLOT_MALLOC, SLOT_ALLOC_ERR = 0x64df4a0, 0x64df480, 0x64df490
SLOT_NEG, SLOT_UNWRAP, SLOT_ASSERT, SLOT_ONCE = 0x64df830, 0x64df6a0, 0x64e1e68, 0x64df9f0
ONCE_FLAG = 0x64f01d8
LANDING = {LOADER: 0x3c12a33, BOUNDARY: 0x3c135d7, BUILDER: 0x3c136bf}   # first landing-pad instruction of each FDE
FUNCS = ((LOADER, "loader"), (BOUNDARY, "boundary"), (BUILDER, "builder"))
HELPERS = {PREP: "prep", NAME: "name", LOOKUP: "lookup", DROP: "drop", FIX_A: "fix_a", FIX_B: "fix_b",
           BOUNDARY: "boundary (slot)", BUILDER: "builder (slot)", BODY: "materializer (slot)", 0x635de30: "dealloc",
           0x6355830: "malloc", 0x141e251: "alloc_error", 0x3c374e0: "fix_a2 (slot)", 0x3bec320: "fix_c (slot)",
           0x5c87d50: "once slow path", 0x1680c10: "panic_neg", 0x1680c30: "unwrap_failed", 0x167bbeb: "assert_failed",
           0x1680cab: "cold call (landing pad)"}

E = mat.ENTRY_SP
L = -0xb0                  # loader rsp relative to E: ret + six pushes + 0x78
A_COPY, B_COPY = L - 0x70, L - 0x50     # boundary frame copies of P (32 bytes) and B (48 bytes)
O = L - 0x4350             # builder rsp = output buffer on its stack; the materializer entry sp
IN_SIZE, OUT_SIZE = mat.IN_SIZE, mat.OUT_SIZE
ARG_AT, NAME_AT, HEAP_AT = 0x7d00_0300_0000, 0x7d00_0400_0000, 0x7d00_0500_0000
HEAP_FILL = 0xa7
B_OFF = 0x40
CASES = 12000
SAVED_REGS, SAVED = mat.SAVED_REGS, mat.SAVED


class Terminal(Exception):
    def __init__(self, kind, args):
        super().__init__(kind)
        self.kind, self.args = kind, args


def sym(v):
    for base, size, tag in ((ARG_AT, 0x100, "args"), (NAME_AT, 0x40, "name"), (mat.IN_AT, IN_SIZE, "in"),
                            (HEAP_AT, OUT_SIZE + 0x40, "heap")):
        if base <= v < base + size:
            return (tag, v - base)
    if mat.STACK_TOP - 0x10000 <= v < mat.STACK_TOP:
        return ("stack", v - E)
    return ("abs", v)


# ---------------------------------------------------------------- cases
CMODES = ("ok", "ok", "ok-once", "ok-allocfail", "ok-assertfail", "ok-name0", "ok-sat", "err", "err-b0", "err-p0",
          "err-both0", "neg-overflow", "ok-lookup2", "ok-lookupmax", "ok-p0", "err-once", "ok-ramp", "ok")


def rnd(s, bits=64):
    return int.from_bytes(s.take(8), "little") >> (64 - bits if bits < 64 else 0)


def far(s):
    return 0x6a00_0000_0000 + (rnd(s) % (1 << 40))


def make_case(s, idx):
    mode = CMODES[idx % len(CMODES)]
    c = mat.make_case(s, idx)
    c["cmode"] = mode
    r15 = rnd(s)
    c["w"] = [rnd(s) >> s.below(64), far(s), rnd(s), r15]
    p0 = rnd(s) >> s.below(63)
    if mode in ("err-p0", "err-both0", "ok-p0"):
        p0 = 0
    if mode == "neg-overflow":
        p0 = 1 << 63
    elif p0 == 1 << 63:
        p0 = 0
    c["p"] = [p0, far(s), rnd(s), rnd(s)]
    c["n"] = [rnd(s) >> s.below(64), far(s), s.below(64)]
    if mode == "ok-name0":
        c["n"][0] = 0
    c["b"] = [rnd(s) >> s.below(64), far(s), rnd(s), rnd(s), rnd(s), rnd(s)]
    if mode in ("err-b0", "err-both0"):
        c["b"][0] = 0
    c["err"] = rnd(s)
    c["rax"] = {"ok-lookup2": 2, "ok-lookupmax": M64}.get(mode, 1 if mode.startswith("err") else 0)
    c["once"] = (1 + s.below(0xffffffff)) if mode in ("ok-once", "err-once") else 0
    c["allocfail"] = mode == "ok-allocfail"
    inb = bytearray(c["in"])
    inb[0x28:0x30] = (r15 ^ (1 << s.below(64)) if mode == "ok-assertfail" else r15).to_bytes(8, "little")
    sat = {"ok-sat": M64 - (idx // len(CMODES)) % 2}.get(mode)
    if sat is not None:
        inb[0x18:0x20] = sat.to_bytes(8, "little")
    c["in"] = bytes(inb)
    c["a"], c["b_arg"] = E + A_COPY, E + B_COPY
    return c


def all_cases(count=CASES):
    s = mat.Stream("re16-state-load-chain-115")
    for k in range(count):
        yield make_case(s, k)


# ---------------------------------------------------------------- reconstruction
def u64(buf, off):
    return int.from_bytes(buf[off:off + 8], "little")


def _frame_fill():
    """Builder output buffer before the call: stack fill, except the four zero words the 0x1000-byte stack probes write."""
    buf = bytearray([mat.STACK_FILL]) * (OUT_SIZE + mat.OUT_SLACK)
    for k in range(1, 5):
        buf[0x42c8 - 0x1000 * k:0x42c8 - 0x1000 * k + 8] = bytes(8)
    return bytes(buf)


BUILDER_FRAME_FILL = _frame_fill()


def model(c, mut=frozenset()):
    """Pure reconstruction of the whole chain: (calls, terminal, return value, box bytes, input bytes after)."""
    w, p, n, b = c["w"], c["p"], c["n"], c["b"]
    r15 = w[3]
    calls, heap, term = [], bytearray([HEAP_FILL]) * (OUT_SIZE + 0x40), None
    inb = c["in"]
    if c["once"] and "no_once" not in mut:
        calls.append(("once", ONCE_FLAG, 1, ("stack", L), 0x63fe250, 0x63fe278))
    calls.append(("prep", ("stack", L), ("stack", L + 0x20), r15, w[0], w[1], w[2]))
    if p[0] == 1 << 63 and "neg_ignored" not in mut:
        return calls, ("panic_neg", 0x6476750), None, bytes(heap), inb
    calls.append(("name", ("stack", L + 0x38), 0x6476768))
    calls.append(("lookup", n[1], n[2], 0x64767a8))
    ok = c["rax"] != 1 if "lookup_inverted" not in mut else c["rax"] == 0
    if not ok:
        err = [("dealloc", sym(b[1]), b[0], 0)] if b[0] else []
        err.append(("drop", ("args", B_OFF + 0x18)))
        tail = [("dealloc", sym(p[1]), p[0], 0)] if p[0] and "skip_err_free_a" not in mut else []
        calls += (err + tail) if "drop_order" not in mut else (tail + err)
        return calls, ("unwrap_failed", 0x7bc44d, 0x2b, ("stack", L), c["err"], 0x6478118, 0x6476778), None, bytes(heap), inb
    ma = c["a"], c["b_arg"]
    if "composer_args_swapped" in mut:
        ma = ma[1], ma[0]
    mc = {"in": inb, "composed": c["composed"], "out": BUILDER_FRAME_FILL, "a": ma[0], "b": ma[1],
          "consumed": c["consumed"], "inner": c["inner"]}
    mm = mat.model(mc)
    for kind, *args in mm["calls"]:
        def rebase(x):
            if isinstance(x, tuple) and x[0] == "stack":
                return ("stack", O + x[1])
            if isinstance(x, tuple) and x[0] == "out":
                return ("stack", O + x[1])
            return x
        calls.append((kind, *[rebase(x) for x in args]))
    box = mm["out"][:OUT_SIZE]
    size = OUT_SIZE if "malloc_size" not in mut else OUT_SIZE - 8
    calls.append(("malloc", size))
    if c["allocfail"]:
        return calls, ("alloc_error", 8, OUT_SIZE), None, bytes(heap), mm["in"]
    calls.append(("memcpy", ("heap", 0), ("stack", O), OUT_SIZE))
    heap[:OUT_SIZE] = box
    if "skip_free_in" not in mut:
        calls.append(("dealloc", ("in", 0), IN_SIZE, 0))
    if n[0] and "name_free_always" not in mut or "name_free_always" in mut:
        calls.append(("dealloc", sym(n[1]), n[0], 0))
    left = u64(box, 0x28)
    if "no_assert" not in mut and ((left != r15) if "assert_ne" not in mut else (left == r15)):
        return calls, ("assert_failed", 0, ("stack", L + 0x58), ("stack", L + 0x50), 0, 0x6476790, left, r15), None, \
            bytes(heap), mm["in"]
    box = bytearray(box)
    box[0x10:0x18] = r15.to_bytes(8, "little")
    cur = u64(box, 0x18)
    box[0x18:0x20] = ((cur + 1) & M64 if "inc_wrap" in mut else (cur + 1 if cur != M64 else M64)).to_bytes(8, "little")
    src = 0x28 if "field20_from_28" in mut else 0x30
    box[0x20:0x28] = box[src:src + 8]
    box[0x10e8:0x10f0] = bytes(8 if "clear_4" not in mut else 4) + (box[0x10ec:0x10f0] if "clear_4" in mut else b"")
    box[0xdf0:0xdf8] = box[0x30:0x38]
    box[0xef8:0xf00] = box[0x30:0x38]
    calls += [("fix_a", ("heap", 0xd88)), ("fix_a2", ("heap", 0xd88))]
    if "skip_fix_b" not in mut:
        calls.append(("fix_b", ("heap", 0xed8)))
    calls.append(("fix_c", ("heap", 0x40c0 if "fix_c_arg" not in mut else 0x40c8)))
    box[0x3e28:0x3e2a] = bytes(2)
    box[0x3ee0:0x3ee2] = bytes(2)
    box[0x39b0] = 2 if "flag_3" not in mut else 3
    if w[0]:
        calls.append(("dealloc", sym(w[1]), w[0], 0))
    heap[:OUT_SIZE] = bytes(box)
    return calls, None, HEAP_AT, bytes(heap), mm["in"]


MODEL_MUTANTS = ["inc_wrap", "no_once", "assert_ne", "no_assert", "neg_ignored", "lookup_inverted", "drop_order",
                 "skip_err_free_a", "name_free_always", "field20_from_28", "clear_4", "skip_fix_b", "fix_c_arg",
                 "flag_3", "malloc_size", "skip_free_in", "composer_args_swapped"]


# ---------------------------------------------------------------- harness
def clobber(mm, ret):
    mat.clobber(mm, ret)


def install(m, c, rec, drops):
    img = m.image

    def stub(target, fn):
        m.stubs[target] = fn

    def memcpy(mm):
        dst, src, size = mm.regs[7], mm.regs[6], mm.regs[2]
        rec.append(("memcpy", sym(dst), sym(src), size))
        mm.store_bytes(dst, mm.load_bytes(src, size))
        clobber(mm, dst)

    def composer(mm):
        dst, src = mm.regs[7], mm.regs[6]
        rec.append(("composer", sym(dst), sym(src), mm.regs[2], mm.regs[1]))
        mm.store_bytes(dst, c["composed"])
        if sym(src)[0] == "in":
            mm.store_bytes(src, c["consumed"][:max(0, min(mat.SUB_SIZE, mat.IN_AT + IN_SIZE - src))])
        clobber(mm, dst)

    def prep(mm):
        dst, src, r = mm.regs[7], mm.regs[6], mm.regs[2]
        rec.append(("prep", sym(dst), sym(src), r, mm.load(src, 8), mm.load(src + 8, 8), mm.load(src + 16, 8)))
        for k, v in enumerate(c["p"]):
            mm.store(dst + 8 * k, 8, v)
        clobber(mm, dst)

    def name(mm):
        dst = mm.regs[7]
        rec.append(("name", sym(dst), mm.regs[6]))
        for k, v in enumerate(c["n"]):
            mm.store(dst + 8 * k, 8, v)
        clobber(mm, dst)

    def lookup(mm):
        rec.append(("lookup", mm.regs[7], mm.regs[6], mm.regs[2]))
        clobber(mm, c["rax"])
        mm.regs[2] = c["err"] if c["rax"] == 1 else mat.IN_AT

    def note(label):
        def fn(mm):
            rec.append((label, sym(mm.regs[7])))
            clobber(mm, 0)
        return fn

    def drop(mm):
        rec.append(("drop", sym(mm.regs[7])))
        clobber(mm, 0)

    def dealloc(mm):
        rec.append(("dealloc", sym(mm.regs[7]), mm.regs[6], mm.regs[2]))
        clobber(mm, 0)

    def malloc(mm):
        rec.append(("malloc", mm.regs[7]))
        clobber(mm, 0 if c["allocfail"] else HEAP_AT)

    def once(mm):
        rec.append(("once", mm.regs[7], mm.regs[6], sym(mm.regs[2]), mm.regs[1], mm.regs[8]))
        mm.store(ONCE_FLAG, 4, 0)
        clobber(mm, 0)

    def terminal(kind, nargs):
        def fn(mm):
            args = [mm.regs[r] for r in (7, 6, 2, 1, 8, 9)][:nargs]
            raise Terminal(kind, args)
        return fn

    if img.import_name(mat.MEMCPY_SLOT) != "memcpy":
        fail("memcpy slot does not name memcpy")
    rel = img.relative
    stub(rel[mat.MEMCPY_SLOT], memcpy)
    stub(mat.COMPOSER, composer)
    stub(PREP, prep)
    stub(NAME, name)
    stub(LOOKUP, lookup)
    stub(DROP, drop)
    stub(FIX_A, note("fix_a"))
    stub(FIX_B, note("fix_b"))
    stub(rel[SLOT_FIX_A2], note("fix_a2"))
    stub(rel[SLOT_FIX_C], note("fix_c"))
    stub(rel[SLOT_DEALLOC], dealloc)
    stub(rel[SLOT_MALLOC], malloc)
    stub(rel[SLOT_ONCE], once)
    stub(rel[SLOT_NEG], terminal("panic_neg", 1))
    stub(rel[SLOT_UNWRAP], terminal("unwrap_failed", 5))
    stub(rel[SLOT_ASSERT], terminal("assert_failed", 6))
    stub(rel[SLOT_ALLOC_ERR], terminal("alloc_error", 2))
    for f in drops:
        m.stubs.setdefault(f, "landing")


def run_case(m, c, drops):
    m.reset()
    rec = []
    install(m, c, rec, drops)
    m.regions[0][2][:] = bytes([mat.STACK_FILL]) * len(m.regions[0][2])
    args = m.add_region(ARG_AT, 0x100)
    for k, v in enumerate(c["w"]):
        mat.put(args, 8 * k, 8, v)
    for k, v in enumerate(c["b"]):
        mat.put(args, B_OFF + 8 * k, 8, v)
    orig_args = bytes(args)
    m.add_region(NAME_AT, 0x40)
    inb = m.add_region(mat.IN_AT, IN_SIZE, c["in"])
    heap = m.add_region(HEAP_AT, OUT_SIZE + 0x40, bytes([HEAP_FILL]) * (OUT_SIZE + 0x40))
    m.add_region(ONCE_FLAG, 8, c["once"].to_bytes(8, "little"))
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6] = ARG_AT, ARG_AT + B_OFF
    term, ret = None, None
    try:
        m.run(LOADER, limit=8000)
        ret = m.regs[0]
    except Terminal as t:
        a = t.args
        if t.kind == "unwrap_failed":
            term = (t.kind, a[0], a[1], sym(a[2]), m.load(a[2], 8), a[3], a[4])
        elif t.kind == "assert_failed":
            term = (t.kind, a[0], sym(a[1]), sym(a[2]), a[3], a[5], m.load(a[1], 8), m.load(a[2], 8))
        else:
            term = (t.kind, *a)
    regs_ok = term is not None or ([m.regs[k] for k in SAVED_REGS] == SAVED and m.regs[4] == E)
    return {"calls": rec, "term": term, "ret": ret, "heap": bytes(heap), "in": bytes(inb), "args_same": bytes(args) == orig_args,
            "regs_ok": regs_ok}


def compare(c, want, got):
    calls, term, ret, heap, after_in = want
    ok = got["calls"] == calls and got["term"] == term and got["ret"] == ret and got["regs_ok"] and got["args_same"]
    if ok and (term is None or term[0] == "assert_failed"):
        ok = got["heap"] == heap and got["in"] == after_in
    return ok


def evaluate(image, drops, cases, override=None, mut=frozenset(), stop_on_first=False, keep=None):
    m = mat.TraceMachine(image, override)
    bad = n = 0
    classes = {}
    for i, c in enumerate(cases):
        want = model(c, mut)
        try:
            got = run_case(m, c, drops)
            ok = compare(c, want, got)
        except (ToolError, KeyError) as exc:
            got, ok = {"error": f"{type(exc).__name__}: {exc}", "calls": [], "term": None, "ret": None, "heap": b""}, False
        except Boundary as exc:
            got, ok = {"error": f"reached {exc.kind} stub", "calls": [], "term": None, "ret": None, "heap": b""}, False
        n += 1
        bad += not ok
        key = c["cmode"] + "/" + ("error" if "error" in got else (got["term"][0] if got["term"] else "returned"))
        classes[key] = classes.get(key, 0) + 1
        if keep is not None:
            keep(i, c, got, ok)
        if stop_on_first and not ok:
            break
    return n, bad, classes, m


# ---------------------------------------------------------------- static evidence
CHECKED = (
    (LOADER + 0x14, "8b 05 be d9 8d 02", "loader reads dword [0x64f01d8] (one-time-init gate)"),
    (0x3c12847, "e8 d4 63 85 00", "loader calls prep 0x4468c20"),
    (0x3c12853, "48 f7 d8", "neg rax: P0 == i64::MIN is the only value that sets OF"),
    (0x3c12856, "0f 80 82 01 00 00", "jo -> panic 0x3c129de (slot 0x64df830, message 0x6476750)"),
    (0x3c12877, "e8 04 95 cc ff", "loader calls 0x38dbd80 (string producer) with rsi = 0x6476768"),
    (0x3c128a2, "ff 15 80 6d 8d 02", "loader calls the boundary through slot 0x64e9628"),
    (0x3c128ab, "48 83 f8 01", "rax == 1 is the boundary error arm"),
    (0x3c128d7, "0f 85 39 01 00 00", "assert_eq failure branch when box[0x28] != r15"),
    (0x3c128ec, "48 ff c0", "inc rax; cmovne keeps -1 on wrap: saturating +1 of box[0x18]"),
    (0x3c12904, "49 c7 84 24 e8 10 00 00 00 00 00 00", "box[0x10e8] = 0 (8 bytes)"),
    (0x3c12959, "66 41 c7 84 24 28 3e 00 00 00 00", "box[0x3e28] = 0 (16 bit)"),
    (0x3c12964, "66 41 c7 84 24 e0 3e 00 00 00 00", "box[0x3ee0] = 0 (16 bit)"),
    (0x3c1296f, "41 c6 84 24 b0 39 00 00 02", "box[0x39b0] = 2 (8 bit)"),
    (0x3c1352f, "48 8d 15 72 32 86 02", "boundary passes the constant 0x64767a8 as lookup rdx"),
    (0x3c1353b, "48 83 f8 01", "boundary error arm test rax == 1"),
    (0x3c13558, "49 83 c6 18", "drop glue receives B + 0x18"),
    (0x3c135c2, "ff 15 d8 3d 8d 02", "boundary calls the builder through slot 0x64e73a0"),
    (0x3c13613 - 1, "53", "builder pushes rbx"),
    (0x3c1364f, "48 81 ec c8 02 00 00", "builder frame tail 0x2c8 (4 probed pages + 0x2c8 = 0x42c8 output buffer)"),
    (0x3c13665, "ff 15 c5 5f 8d 02", "builder calls the materializer through slot 0x64e9630"),
    (0x3c1366b, "bf c8 42 00 00", "builder allocates 0x42c8 bytes"),
    (0x3c1367e, "ba c8 42 00 00", "builder copies 0x42c8 bytes into the allocation"),
    (0x3c1368f, "be a8 27 00 00", "builder frees the 0x27a8-byte input"),
    (0x3c136ad, "bf 08 00 00 00 be c8 42 00 00", "allocation failure: alloc error (align 8, size 0x42c8)"),
)


def slot_users(image, slot):
    t, d = image.text, image.data
    base, hi, out = t["address"] - t["offset"], t["offset"] + t["size"] - 6, []
    for sig in (b"\xff\x15", b"\xff\x25"):
        pos = d.find(sig, t["offset"], hi)
        while pos != -1:
            if pos + base + 6 + struct.unpack_from("<i", d, pos + 2)[0] == slot:
                out.append(pos + base)
            pos = d.find(sig, pos + 1, hi)
    return sorted(out)


def static_evidence(image):
    rows = mat.fde_rows(image, [f for f, _ in FUNCS])
    funcs, calls, drops, decoded_all = {}, [], [], {}
    for start, name in FUNCS:
        lo, hi = rows[start]
        decoded = mat.sweep_padded(image, lo, hi)
        decoded_all[start] = decoded
        land = LANDING[start]
        if image.code(land, 3) not in (bytes.fromhex("4989c5"), bytes.fromhex("4989c7"), bytes.fromhex("4989c6")):
            fail(f"landing pad start of {name} moved")
        funcs[name] = {"start": f"{lo:#x}", "fde_end": f"{hi:#x}", "fde_bytes": hi - lo,
                       "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                       "instructions": sum(1 for _, fm in decoded if fm is not None), "landing_pad": f"{land:#x}"}
        for va, kind, target in mat.call_sites(decoded, lo, hi):
            tgt = target
            if kind == "got":
                tgt = image.relative.get(target)
            region = "landing-pad" if va >= land else "normal"
            if kind == "direct" and target == mat.UNWIND_RESUME:
                role = "_Unwind_Resume"
            elif kind == "got" and target == mat.MEMCPY_SLOT:
                role = "memcpy"
            elif tgt in HELPERS:
                role = HELPERS[tgt]
            elif kind == "register":
                role = "register call"
            else:
                role = "other"
            if region == "landing-pad" and kind == "direct" and role == "other":
                drops.append(target)
            calls.append({"function": name, "site": f"{va:#x}", "kind": kind,
                          "slot": f"{target:#x}" if kind == "got" else "-",
                          "target": f"{tgt:#x}" if tgt is not None else "reg", "role": role, "region": region})
    checks = {}
    for va, hx, what in CHECKED:
        want = bytes.fromhex(hx)
        if image.code(va, len(want)) != want:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want.hex(), "meaning": what}
    slots = {}
    for name, slot, target in (("loader", SLOT_LOADER, LOADER), ("boundary", SLOT_BOUNDARY, BOUNDARY),
                               ("builder", SLOT_BUILDER, BUILDER), ("materializer", SLOT_BODY, BODY)):
        if image.relative.get(slot) != target:
            fail(f"slot {slot:#x} no longer points at {target:#x}")
        slots[name] = {"slot": f"{slot:#x}", "addend": f"{target:#x}",
                       "call_sites": [f"{v:#x}" for v in slot_users(image, slot)],
                       "direct_e8_sites": [f"{v:#x}" for v in mat.caller_scan(image, target)[0]],
                       "relative_addends": [f"{v:#x}" for v in mat.caller_scan(image, target)[1]]}
    if slots["loader"]["call_sites"] != [f"{LOADER_CALL_SITE:#x}"]:
        fail("loader slot call sites changed")
    if slots["boundary"]["call_sites"] != ["0x3c128a2"] or slots["materializer"]["call_sites"] != ["0x3c13665"]:
        fail("boundary or materializer slot users changed")
    helper_slots = {}
    for label, slot in (("fix_a2", SLOT_FIX_A2), ("fix_c", SLOT_FIX_C), ("dealloc", SLOT_DEALLOC), ("malloc", SLOT_MALLOC),
                        ("alloc_error", SLOT_ALLOC_ERR), ("panic_neg", SLOT_NEG), ("unwrap_failed", SLOT_UNWRAP),
                        ("assert_failed", SLOT_ASSERT), ("once", SLOT_ONCE)):
        helper_slots[label] = {"slot": f"{slot:#x}", "target": f"{image.relative[slot]:#x}"}
    return {"binary_sha256": SHA256, "functions": funcs, "slots": slots, "helper_slots": helper_slots,
            "checked_bytes": checks, "frames": {"loader_rsp": L, "boundary_rsp": L - 0x70, "p_copy": A_COPY,
                                                  "b_copy": B_COPY, "builder_rsp": O},
            "sizes": {"input": IN_SIZE, "output": OUT_SIZE}}, calls, sorted(set(drops)), decoded_all


# ---------------------------------------------------------------- controls
BYTE_MUTANTS = [
    (0x3c128ae, 0x01, 0x02, "boundary error arm test rax == 1 -> rax == 2 (loader)"),
    (0x3c12977, 0x02, 0x03, "box[0x39b0] = 2 -> 3"),
    (0x3c12908, 0xe8, 0xe0, "box[0x10e8] -> box[0x10e0]"),
    (0x3c1293a, 0xf8, 0xf0, "box[0xef8] -> box[0xef0]"),
    (0x3c12942, 0xd8, 0xd0, "fix_b argument 0xed8 -> 0xed0"),
    (0x3c1294f, 0xc0, 0xc8, "fix_c argument 0x40c0 -> 0x40c8"),
    (0x3c1291c, 0x88, 0x80, "fix_a argument 0xd88 -> 0xd80"),
    (0x3c128ee, 0xc0, 0xc8, "inc rax -> dec rax (box[0x18])"),
    (0x3c128d8, 0x85, 0x84, "assert_eq jne -> je"),
    (0x3c12857, 0x80, 0x81, "jo -> jno after the neg"),
    (0x3c12848, 0xd4, 0xd0, "prep call target moved by 4"),
    (0x3c1281d, 0x85, 0x84, "once gate jne -> je"),
    (0x3c1353e, 0x01, 0x02, "boundary error arm test rax == 1 -> rax == 2"),
    (0x3c1355b, 0x18, 0x20, "drop glue argument B+0x18 -> B+0x20"),
    (0x3c13532, 0x72, 0x7a, "lookup constant 0x64767a8 -> 0x64767b0"),
    (0x3c13567 + 1, 0x01, 0x00, "boundary error return 1 -> 0"),
    (0x3c1366c, 0xc8, 0xc0, "builder allocation size 0x42c8 -> 0x42c0"),
    (0x3c1367f, 0xc8, 0xc0, "builder copy length 0x42c8 -> 0x42c0"),
    (0x3c13690, 0xa8, 0xa0, "builder frees 0x27a8 -> 0x27a0"),
    (0x3c13652, 0xc8, 0xc0, "builder frame tail 0x2c8 -> 0x2c0"),
    (0x3c13657, 0x89, 0x8b, "builder rdx -> rcx move turned into a load form"),
    (0x3c136b3, 0xc8, 0xc0, "alloc error size 0x42c8 -> 0x42c0"),
]


def controls(image, cases, drops):
    rows = []
    for name in MODEL_MUTANTS:
        n, bad, _, _ = evaluate(image, drops, cases, mut=frozenset([name]), stop_on_first=True)
        rows.append(("model", name, int(bad > 0)))
    for va, old, new, what in BYTE_MUTANTS:
        if image.code(va, 1)[0] != old:
            fail(f"byte mutant at {va:#x} does not start from {old:#04x}")
        n, bad, _, _ = evaluate(image, drops, cases, override={va: new}, stop_on_first=True)
        rows.append(("code", f"{va:#x}={new:#04x} {what}", int(bad > 0)))
    corrupt = bytearray(image.data)
    corrupt[image.text["offset"] + 7] ^= 1
    for label, fn in (("input", lambda: mat.Image(bytes(corrupt))),
                      ("input-range", lambda: image.code(image.text["address"] + image.text["size"] + 0x100, 4))):
        try:
            fn()
            rows.append(("input", label, 0))
        except ToolError:
            rows.append(("input", label, 1))
    # out-of-range structural controls: wrong function start and a wrong slot target are rejected by the static checks
    for label, patch in (("slot target wrong", lambda r: r.__setitem__(SLOT_BOUNDARY, BUILDER)),
                         ("slot target wrong (loader)", lambda r: r.__setitem__(SLOT_LOADER, BOUNDARY))):
        saved = dict(image.relative)
        patch(image.relative)
        try:
            static_evidence(image)
            rows.append(("static", label, 0))
        except ToolError:
            rows.append(("static", label, 1))
        finally:
            image.relative.clear()
            image.relative.update(saved)
    return rows


# ---------------------------------------------------------------- output
def sha16(b):
    return hashlib.sha256(b).hexdigest()[:16]


def generate(out):
    image = mat.Image(BINARY.read_bytes())
    ev, call_rows, drops, decoded_all = static_evidence(image)
    mat_ev, _, _, mat_pad_drops = mat.static_evidence(image)
    drops = sorted(set(drops) | set(mat_pad_drops))
    out.mkdir(parents=True, exist_ok=True)
    case_lines = ["case\tmode\toutcome\tcalls\tret\tbox_sha256_16\tmatch"]
    first_trace = {}

    def keep(i, c, got, ok):
        if i % 2 == 0:
            kind = got["term"][0] if got.get("term") else ("error" if "error" in got else "returned")
            ret = sym(got["ret"]) if got.get("ret") is not None else "-"
            case_lines.append(f"{i}\t{c['cmode']}\t{kind}\t{len(got['calls'])}\t{ret}\t"
                              f"{sha16(got['heap']) if got.get('heap') else '-'}\t{'yes' if ok else 'NO'}")
        if c["cmode"] not in first_trace:
            first_trace[c["cmode"]] = got["calls"] + ([got["term"]] if got.get("term") else [])

    n, bad, classes, m = evaluate(image, drops, all_cases(), keep=keep)
    (out / "cases.tsv").write_text("\n".join(case_lines) + "\n")
    (out / "outcome-classes.tsv").write_text(
        "outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    flow = ["mode\tstep\tevent"]
    for mode in dict.fromkeys(CMODES):
        for k, ev_ in enumerate(first_trace.get(mode, [])):
            flow.append(f"{mode}\t{k}\t{ev_}")
    (out / "flow.tsv").write_text("\n".join(flow) + "\n")
    (out / "calls.tsv").write_text(
        "function\tsite\tkind\tslot\ttarget\trole\tregion\n"
        + "".join("\t".join(r[k] for k in ("function", "site", "kind", "slot", "target", "role", "region")) + "\n"
                  for r in call_rows))
    lines = ["function\taddress\tbytes\tregion\texecuted"]
    hit = {}
    for start, name in FUNCS:
        for va, f in decoded_all[start]:
            if f is None:
                continue
            region = "landing-pad" if va >= LANDING[start] else "body"
            run = int(va in m.seen)
            lines.append(f"{name}\t{va:#x}\t{f['bytes'].hex()}\t{region}\t{run}")
            if region == "body":
                h = hit.setdefault(name, [0, 0])
                h[0] += run
                h[1] += 1
    (out / "instructions.tsv").write_text("\n".join(lines) + "\n")
    (out / "constants.json").write_text(json.dumps(ev, indent=2, sort_keys=True) + "\n")
    ctl = controls(image, [c for _, c in zip(range(200), all_cases())], drops)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    summary = {"binary_sha256": SHA256, "cases": n, "mismatches": bad, "body_instructions_executed": hit,
               "outcome_classes": len(classes), "negative_controls": {"total": len(ctl), "detected": sum(r[2] for r in ctl)}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps(
        {"cases": n, "negative_controls": len(ctl), "negative_detected": sum(r[2] for r in ctl)}, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    args = ap.parse_args(argv)
    try:
        summary = generate(args.out)
    except ToolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    bad = summary["mismatches"] or summary["negative_controls"]["detected"] != summary["negative_controls"]["total"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
