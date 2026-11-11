#!/usr/bin/env python3
"""Reconstruct and validate the node #115 state-file writer pair 0x422ed40 / 0x422f030 and its result plumbing.

Observed contract (all from machine code; role names are inferences):
  writer(rdi = value, rsi = path ptr, rdx = path len, rcx = extra) -> rax
  1. a path of exactly nine bytes "/dev/null" returns 0 before any other work;
  2. 0x5cab560-style resolver (GOT 0x64e0938) is asked about the path with the 0x26-byte request {ptr, len, tag 6, flags 0x0201,
     is_abs}; result tag 9 carries the normalised string, anything else routes to the text serializer;
  3. extension rule (last '.', '..' and hidden-dot rejected, 3 bytes equal "rmp" ignoring ASCII case via 0x159fca0) picks the binary
     serializer; every other string uses the text serializer with a freshly allocated 0x80-byte buffer;
  4. binary branch: empty Vec {cap 0, ptr 1, len 0}, options {vec ptr, dword 0x1000400, byte 0}; word0 == i64::MIN|4 is Ok.
     Twin A calls 0x3c13960, twin B calls 0x38c20b0 (run here as real code, see below);
  5. text branch: Vec {cap 0x80, ptr, len 0}, options {vec ptr, 0x7c809e, 2, 0, 0}; allocation failure ends in the noreturn handler;
     rax != 0 is an error pointer, cap == i64::MIN is the niche error arm;
  6. write phase: precheck GOT 0x64e0028(path); on 0 the write GOT 0x64e09e8(buf, len, path, extra) result is returned;
     the Vec buffer is freed when cap != 0;
  7. error arms go through the context wrappers 0x422f670 (boxed error, tag 0 = owned buffer, tag 1 = nested) and 0x422f740
     (inline error, word0 niche encoding), which are reconstructed as units too.
The twin 0x422f030 differs from 0x422ed40 only in the two serializer calls (0x38c20b0 / 0x38c2230 for 0x3c13960 / 0x3c136f0).
The three-field struct serializer 0x38c20b0 is reconstructed as a unit and run for real inside twin B.
The tool runs the real machine code with the concrete evaluator of tools/re16_state_materialize115.py (imports and unowned callees are
stubs that scramble caller-saved registers) and compares each case with the pure-Python models, including the call trace.
The binary is never executed.
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
    """mat.decode plus the 66-prefixed 16-bit immediates of c7 /0 and 81 /n."""
    form = _decode(code, va)
    if form["op"] in (0xc7, 0x81) and form["p66"]:
        at = form["len"] - 4
        form["imm"] = struct.unpack_from("<h", code, at)[0]
        form["len"] = at + 2
        form["bytes"] = bytes(code[:form["len"]])
    return form


mat.decode = decode16

MIN64 = 1 << 63
OKW = MIN64 | 4                      # the Ok marker of the serializer result words
WA, WB, EW, E670, E740, SER = 0x422ed40, 0x422f030, 0x422f024, 0x422f670, 0x422f740, 0x38c20b0
PRE, CTXB = 0x15020f0, 0x43034f0
ENDS = {WA: 0x422f024, WB: 0x422f314, E670: 0x422f735, E740: 0x422f7f9, SER: 0x38c2224, PRE: 0x15021c2, CTXB: 0x430352a}
E = mat.ENTRY_SP
FRAME = {WA: -0xd0, WB: -0xd0, E670: -0x40, E740: -0x40, SER: -0x50, PRE: -0x90, CTXB: -0x30}   # body rsp relative to the entry rsp
SER_IN_W = FRAME[WB] - 0x50                                           # 0x38c20b0 frame when called from the writer
SLOT = {"resolve": 0x64e0938, "alloc": 0x64df480, "alloc_err": 0x64df498, "dealloc": 0x64df4a0, "pre": 0x64e0028,
        "write": 0x64e09e8, "lookup": 0x64e09b0, "convert": 0x64dfca8, "exists": 0x64e0928, "mkdir": 0x64e0940,
        "format": 0x64df6e8}
STUB = {"rmp_a": 0x3c13960, "json_a": 0x3c136f0, "json_b": 0x38c2230, "ctx": 0x43034f0, "drop_inner": 0x4232440,
        "w670": E670, "w740": E740, "hdr_plain": 0x3d50270, "hdr_named": 0x3d4f6d0, "name": 0x41c6110, "sub": 0x36c5b50}
EQ_NOCASE, EXT_AT, JSON_TAG_AT = 0x159fca0, 0x4659e5, 0x7c809e
FMT_AT, VT_AT, GOT_670, GOT_740 = 0x44e417, 0x46dd7f0, 0x64e01a8, 0x64e0a48
NAMES = ((0x7a1422, 0xd), (0x7a142f, 0xe), (0x7a143d, 0xc))
SUBOFF = (0, 0x810, 0x1020)
PATH_AT, NORM_AT, ERR_AT, OUT_AT, VEC_AT, ARGS_AT = (0x7d00_0100_0000, 0x7d00_0300_0000, 0x7d00_0400_0000, 0x7d00_0500_0000,
                                                       0x7d00_0600_0000, 0x7d00_0700_0000)
VALUE = 0x7d00_0800_0000
REGION = 0x100
PER_UNIT = {WA: 2800, WB: 2800, E670: 2400, E740: 2400, SER: 2800, PRE: 2600, CTXB: 1600}
SAVED_REGS, SAVED = mat.SAVED_REGS, mat.SAVED
DEVNULL = b"/dev/null"
NAMEOF = {WA: "writer_a", WB: "writer_b", E670: "wrap_boxed", E740: "wrap_inline", SER: "struct3", PRE: "precheck", CTXB: "context_builder"}
HELPERS = {EQ_NOCASE: "eq_ignore_ascii_case", 0x3c13960: "rmp_serialize_a", 0x3c136f0: "text_serialize_a",
           0x38c2230: "text_serialize_b", 0x43034f0: "context_wrap", 0x4232440: "drop_nested", 0x4232760: "drop_nested_cleanup",
           0x42327b0: "drop_boxed_cleanup", 0x3d50270: "header_plain", 0x3d4f6d0: "header_named", 0x41c6110: "field_name",
           0x36c5b50: "field_value", SER: "struct3", E670: "wrap_boxed", E740: "wrap_inline", 0x63f0a50: "_Unwind_Resume",
           0x635de30: "dealloc", 0x5cab560: "resolve", 0x6355830: "alloc", PRE: "precheck", CTXB: "context_builder", 0x1500b90: "precheck_error_wrap", 0x4303130: "context_tail",
           0x43030c0: "wrap_error", 0x141e3a0: "format",
           0x15024a0: "write_buffer", 0x141e264: "alloc_error", 0x1680cab: "cold_stub"}


def A(v):
    return ("abs", v & M64)


def S(base, off):
    return ("stack", base + off)


def sym(v):
    for base, tag in ((PATH_AT, "path"), (NORM_AT, "norm"), (ERR_AT, "err"), (OUT_AT, "out"), (VEC_AT, "vec"),
                      (ARGS_AT, "args")):
        if base <= v < base + REGION:
            return (tag, v - base)
    if mat.STACK_TOP - 0x10000 <= v < mat.STACK_TOP:
        return ("stack", v - E)
    return ("abs", v)


class NoReturn(Exception):
    pass


# ---------------------------------------------------------------- cases
def rnd(s):
    return int.from_bytes(s.take(8), "little")


def small_or_big(s):
    return s.pick((0, 1, 2, 0x20, 0x80, 0xffff)) if s.below(2) else rnd(s) >> s.below(64)


def vec_word_triple(s):
    cap = s.pick((0, 0, 1, 0x80, MIN64, MIN64 + 1, M64)) if s.below(3) else small_or_big(s)
    return (cap, rnd(s), small_or_big(s))


EXTS = (b"rmp", b"RMP", b"rMp", b"Rmp", b"rmP", b"rm", b"rmpx", b"xrmp", b"json", b"", b"r.p", b"rmq", b"smp", b"rnp", b"toml", b"mp")
STEMS = (b"state", b"a", b"x/y", b"/abs/state", b"dir.d/f", b"", b"..", b".", b"...", b"a.b", b"a.rmp", b"./s", b"../s", b".hid")
TAGS = (9, 9, 9, 9, 0, 1, 6, 8, 10, 0x109)


def pick_norm(s):
    k = s.below(8)
    if k == 0:
        return s.pick((b"..", b".", b"", b"...", b".rmp", b".RMP", b"a.", b"a..", b"x.rmp.", b"..rmp", b"a.rmp.rmp"))
    if k == 3:
        return bytes(s.pick(b"abc./rmpRMP") for _ in range(s.below(9)))
    if k == 2:
        return s.pick(STEMS) + s.pick(EXTS)
    return s.pick(STEMS) + b"." + s.pick(EXTS)


def struct_case(s, flag):
    return {"flag": flag, "hdr": (s.pick((2, 2, 2, 2, 2, 2, 2, 0, 1, 3)) if s.below(8) else rnd(s), rnd(s)),
            "names": [(2, rnd(s)) if s.below(4) else (s.pick((0, 1, 3, rnd(s))), rnd(s)) for _ in range(3)],
            "subs": [(OKW, rnd(s), rnd(s)) if s.below(4) else (s.pick((MIN64, MIN64 | 5, 0, rnd(s))), rnd(s), rnd(s))
                     for _ in range(3)],
            "vecs": [vec_word_triple(s) for _ in range(3)]}


def writer_case(s, idx):
    pick = idx % 16
    path = s.pick((b"/node/state.rmp", b"state.rmp", b"", b"/", b"/x", b"rel/s.json", b"\xff/a", b"a", DEVNULL, DEVNULL,
                   b"/dev/nulL", b"/dev/nul", b"/dev/null0", b"xdev/null", b"/dev/nulx"))
    if pick in (0, 1):
        path = DEVNULL
    elif s.below(3) == 0:
        path = bytes(s.take(s.below(20)))
    c = {"idx": idx, "path": path, "extra": rnd(s), "tag": s.pick(TAGS) if pick != 4 else 9, "norm": pick_norm(s)}
    if pick in (5, 6, 7, 8):
        c["norm"], c["tag"] = s.pick(STEMS) + b"." + s.pick((b"rmp", b"RMP", b"rMp")), 9
    if pick in (9, 10):
        c["norm"], c["tag"] = s.pick(STEMS) + b"." + s.pick((b"json", b"rm", b"rmpx", b"xrmp", b"")), 9
    ok = s.below(3) != 0 if pick not in (5, 6) else pick == 5
    c["ser"] = (OKW if ok else s.pick((MIN64, MIN64 | 5, 0, rnd(s), M64)), rnd(s), rnd(s))
    c["vec_ser"] = vec_word_triple(s)
    c["s"] = struct_case(s, 1)
    c["alloc"] = 0 if pick == 11 else (rnd(s) | 0x1000)
    c["jerr"] = 0 if (s.below(3) and pick != 12) else rnd(s) | 1
    c["jvec"] = vec_word_triple(s)
    if pick == 13:
        c["jerr"], c["jvec"] = 0, (MIN64, c["jvec"][1], c["jvec"][2])
    c["pre"] = 0 if (s.below(4) or pick == 14) else rnd(s) | 1
    c["wr"] = rnd(s) if s.below(3) else 0
    c["w670"], c["w740"] = rnd(s), rnd(s)
    c["words"] = (s.pick(TAGS), 0)
    return c


def err_case(s, idx, boxed):
    first = (s.pick((0, 1, 2, 3, 5)) if s.below(2) else rnd(s) >> s.below(64)) if boxed else \
        s.pick((0, 1, 2, 3, 4, 5, MIN64, MIN64 + 1, MIN64 + 2, MIN64 + 3, MIN64 + 4, MIN64 + 5, M64, rnd(s), rnd(s) | MIN64,
                rnd(s) >> 1))
    return {"idx": idx, "slot": rnd(s), "err": [first, rnd(s), rnd(s) if s.below(3) else 0, rnd(s), rnd(s)],
            "ctx": rnd(s)}


def ser_case(s, idx):
    c = struct_case(s, s.pick((1, 1, 1, 0, 2, 0x7f, 0xff)))
    c["idx"], c["vec0"], c["out0"] = idx, vec_word_triple(s), (rnd(s), rnd(s), rnd(s))
    return c


def pre_case(s, idx):
    path = s.pick((b"", b"/", b"/a/b", b"rel", b"/node/state.rmp", b"x")) if s.below(3) else bytes(s.take(s.below(14)))
    return {"idx": idx, "path": path, "norm": b"", "tag": s.pick((7, 8, 9, 9, 6, 10, 0, 1, 0xff, 0x107, 0x208, 0x309, rnd(s))),
            "look": 0 if s.below(3) == 0 else rnd(s) | 1,
            "conv": (s.pick((0, 1, 2, 0x1_0000_0001, 0x1_0000_0000, rnd(s))), rnd(s), small_or_big(s)),
            "ex": s.pick((0, 1, 0x100, 0xff, rnd(s) | 1, rnd(s) & ~0xff)), "mk": 0 if s.below(2) else rnd(s) | 1, "wrapret": rnd(s)}


def ctxb_case(s, idx):
    return {"idx": idx, "a": rnd(s), "b": rnd(s) if idx % 2 else rnd(s) & ~1, "wrapret": rnd(s)}


def all_cases(fn, count):
    s = mat.Stream(f"re16-state-writer-115-{fn:x}")
    for k in range(count):
        yield (writer_case(s, k) if fn in (WA, WB) else err_case(s, k, fn == E670) if fn in (E670, E740) else
               pre_case(s, k) if fn == PRE else ctxb_case(s, k) if fn == CTXB else ser_case(s, k))


# ---------------------------------------------------------------- reconstruction
def ext_of(norm, mut=frozenset()):
    n = len(norm)
    if n == 2 and norm == b".." and "no_dotdot" not in mut:
        return None
    i = n
    while True:
        if i == 0:
            return None
        i -= 1
        if norm[i] == (0x2e if "dot_char" not in mut else 0x2f):
            break
    if i == 0 and "hidden_ok" not in mut:
        return None
    return norm[i + 1:]


def model_ser(c, R, args_sym, dword, vec_in, mut=frozenset()):
    """0x38c20b0: header, three named fields, early exit on the first failure.  Returns (events, out words, vec or None)."""
    ev, flag, vec = [], c["flag"], None
    plain = (flag == 0) != ("hdr_swapped" in mut)
    ev.append(("hdr_plain" if plain else "hdr_named", S(R, 8), args_sym, A(3), dword, vec_in))
    if c["hdr"][0] != 2:
        return ev, (MIN64, c["hdr"][0], c["hdr"][1]), vec
    for k in range(3):
        if flag == 1 or "names_always" in mut:
            ev.append(("name", args_sym, A(NAMES[k][0]), A(NAMES[k][1])))
            if c["names"][k][0] != 2:
                return ev, (MIN64, c["names"][k][0], c["names"][k][1]), vec
        ev.append(("sub", S(R, 8), A(VALUE + SUBOFF[k]), args_sym))
        vec = c["vecs"][k] if "vec_not_updated" not in mut else vec
        if c["subs"][k][0] != OKW:
            return ev, c["subs"][k], vec
    return ev, (OKW, None, None), vec


def model_writer(c, fn, mut=frozenset()):
    """Returns (events, rax or None for the noreturn arm)."""
    R, path = FRAME[fn], c["path"]
    n = len(path)
    ev = []
    if n == 9 and path == DEVNULL and "devnull_off" not in mut:
        return ev, 0
    is_abs = int(n != 0 and path[0] == 0x2f) if "abs_always" not in mut else 1
    ev.append(("resolve", S(R, 0), S(R, 0x38), ("req", ("path", 0), n, 6, 0x0201, is_abs)))
    rmp = False
    if c["tag"] & 0xff == 9:
        e = ext_of(c["norm"], mut)
        if e is not None:
            ev.append(("eq_nocase", len(e), EXT_AT, 3))
            rmp = len(e) == 3 and (e == b"rmp" if "case_sensitive" in mut else e.lower() == b"rmp")
    if "rmp_swapped" in mut:
        rmp = not rmp
    wr_ptr = ("path", 0)
    if rmp:
        args = ("opts", S(R, 0), 0x1000400, 0, (0, 1, 0))
        if fn == WA:
            ev.append(("rmp_ser", S(R, 0x38), A(VALUE), S(R, 0x88), args))
            out, vec = c["ser"], c["vec_ser"]
        else:
            ev2, out3, vecs = model_ser(c["s"], SER_IN_W, S(R, 0x88), 0x1000400, (0, 1, 0), mut)
            ev += ev2
            out, vec = out3, vecs if vecs is not None else (0, 1, 0)
        if (out[0] != OKW) == ("ok_inverted" not in mut):
            cap, ptr, _ = vec
            if cap:
                ev.append(("dealloc", A(ptr), A(cap), A(0)))
            ev.append(("w740", S(R, 0x78), S(R, 0x38), (("path", 0), n), tuple(out)))
            return ev, c["w740"]
        cap, ptr, ln = vec
    else:
        ev.append(("alloc", A(0x80)))
        if c["alloc"] == 0:
            ev.append(("alloc_err", A(1), A(0x80)))
            return ev, None
        ev.append(("text_ser", A(VALUE), S(R, 0x38), ("opts", S(R, 0), JSON_TAG_AT, 2, 0, 0), (0x80, c["alloc"], 0)))
        cap, ptr, ln = c["jvec"]
        if c["jerr"]:
            if cap:
                ev.append(("dealloc", A(ptr), A(cap), A(0)))
            ev.append(("w670", S(R, 0x78), A(c["jerr"]), (("path", 0), n)))
            return ev, c["w670"]
        if cap == MIN64:
            ev.append(("w670", S(R, 0x78), A(ptr), (("path", 0), n)))
            return ev, c["w670"]
    ev.append(("pre", wr_ptr, A(n)))
    rax = c["pre"]
    if rax == 0 or "pre_ignored" in mut:
        ev.append(("write", A(ptr), A(ln), wr_ptr, A(n), A(c["extra"])))
        rax = c["wr"]
    if cap and "free_skipped" not in mut:
        ev.append(("dealloc", A(ptr), A(cap), A(0)))
    return ev, rax


def model_wrap(c, boxed, mut=frozenset()):
    R = FRAME[E670 if boxed else E740]
    ev = [("ctx", A(FMT_AT), S(R, 8), (A(c["slot"]), A(VT_AT), S(R, 0) if boxed else ("err", 0), A(c["got"])))]
    w, p, q = c["err"][:3]
    if boxed:
        if (w == 1) != ("boxed_tag_swapped" in mut):
            ev.append(("drop_inner", ("err", 8)))
        elif w == 0 and (q or "boxed_cap_ignored" in mut):
            ev.append(("dealloc", A(p), A(q), A(0)))
        ev.append(("dealloc", ("err", 0), A(0x28), A(0)))
        return ev, c["ctx"]
    cls = (w ^ MIN64) if w & MIN64 else 4
    if (cls - 1) & M64 < 3:
        return ev, c["ctx"]
    if cls == 0 and "niche_zero_ignored" not in mut:
        ev.append(("drop_inner", ("err", 0x10)))
        return ev, c["ctx"]
    if w or "inline_cap_ignored" in mut:
        ev.append(("dealloc", A(p), A(w), A(0)))
    return ev, c["ctx"]


WRITER_MUT = ["no_dotdot", "dot_char", "hidden_ok", "case_sensitive", "abs_always", "rmp_swapped", "devnull_off", "ok_inverted",
              "pre_ignored", "free_skipped"]
def model_pre(c, mut=frozenset()):
    R, path = FRAME[PRE], c["path"]
    n = len(path)
    ev = [("resolve", S(R, 0x40), S(R, 0), ("req", ("path", 0), n, 6, 0x0201, int(n != 0 and path[0] == 0x2f)))]
    ptr, ln = ("path", 0), n
    lo, hi = (7, 9) if "window" not in mut else (7, 8)
    if lo <= c["tag"] & 0xff <= hi:
        ev.append(("lookup", S(R, 0)))
        if c["look"]:
            ev.append(("convert", S(R, 0), A(c["look"])))
            if (c["conv"][0] & 0xffffffff == 1) == ("convert_ignored" in mut):
                ptr, ln = A(c["conv"][1]), c["conv"][2]
    ev.append(("exists", ptr, A(ln)))
    if c["ex"] & 0xff and "exists_ignored" not in mut:
        return ev, 0
    ev.append(("mkdir", S(R, 0x40), ptr, A(ln), (0x1ff, 1)))
    if c["mk"] == 0:
        return ev, 0
    ev.append(("wrap_err", S(R, 0), A(c["mk"])))
    return ev, c["wrapret"]


def model_ctxb(c, mut=frozenset()):
    R = FRAME[CTXB]
    if (c["b"] & 1) != ("bit_swapped" in mut):
        return [("tail", A(c["a"]), A(c["b"] >> 1 if "no_shift" not in mut else c["b"]))], c["wrapret"]
    return [("fmt", S(R, 8), A(c["a"]), A(c["b"])), ("wrap", S(R, 8))], c["wrapret"]


MODEL_MUTANTS = {PRE: ["window", "convert_ignored", "exists_ignored"], CTXB: ["bit_swapped", "no_shift"], WA: WRITER_MUT, WB: WRITER_MUT, E670: ["boxed_cap_ignored", "boxed_tag_swapped"],
                 E740: ["niche_zero_ignored", "inline_cap_ignored"], SER: ["names_always", "hdr_swapped", "vec_not_updated"]}


# ---------------------------------------------------------------- harness
def install(m, fn, c, rec):
    rel = m.image.relative

    def stub(target, f):
        m.stubs[target] = f

    def args_of(a):
        return (sym(m.load(a, 8)), m.load(a + 8, 4), m.load(a + 0xc, 1))

    def junk_ret(mm, v):
        mat.clobber(mm, v)

    def resolve(mm):
        out, req = mm.regs[7], mm.regs[6]
        rec.append(("resolve", sym(out), sym(req), ("req", sym(mm.load(req, 8)), mm.load(req + 8, 8), mm.load(req + 0x10, 1),
                                                    mm.load(req + 0x38, 2), mm.load(req + 0x3a, 1))))
        mm.store(out, 8, c["tag"])
        mm.store(out + 8, 8, NORM_AT)
        mm.store(out + 16, 8, len(c["norm"]))
        junk_ret(mm, out)

    def set_vec(mm, base, trip):
        for k, v in enumerate(trip):
            mm.store(base + 8 * k, 8, v)

    def rmp_a(mm):
        out, a = mm.regs[7], mm.regs[2]
        vec = mm.load(a, 8)
        rec.append(("rmp_ser", sym(out), sym(mm.regs[6]), sym(a), ("opts", sym(mm.load(a, 8)), mm.load(a + 8, 4), mm.load(a + 0xc, 1),
                                                                       tuple(mm.load(vec + 8 * k, 8) for k in range(3)))))
        set_vec(mm, out, c["ser"])
        set_vec(mm, vec, c["vec_ser"])
        junk_ret(mm, out)

    def alloc(mm):
        rec.append(("alloc", sym(mm.regs[7])))
        junk_ret(mm, c["alloc"])

    def alloc_err(mm):
        rec.append(("alloc_err", sym(mm.regs[7]), sym(mm.regs[6])))
        raise NoReturn()

    def text_ser(mm):
        a = mm.regs[6]
        vec = mm.load(a, 8)
        rec.append(("text_ser", sym(mm.regs[7]), sym(a), ("opts", sym(mm.load(a, 8)), mm.load(a + 8, 8), mm.load(a + 16, 8),
                                                         mm.load(a + 0x18, 8), mm.load(a + 0x20, 1)),
                    tuple(mm.load(vec + 8 * k, 8) for k in range(3))))
        set_vec(mm, vec, c["jvec"])
        junk_ret(mm, c["jerr"])

    def pre(mm):
        rec.append(("pre", sym(mm.regs[7]), sym(mm.regs[6])))
        junk_ret(mm, c["pre"])

    def write(mm):
        rec.append(("write", sym(mm.regs[7]), sym(mm.regs[6]), sym(mm.regs[2]), sym(mm.regs[1]), sym(mm.regs[8])))
        junk_ret(mm, c["wr"])

    def dealloc(mm):
        rec.append(("dealloc", sym(mm.regs[7]), sym(mm.regs[6]), sym(mm.regs[2])))
        junk_ret(mm, 0)

    def w_stub(label, key):
        def f(mm):
            r = mm.regs[6]
            rec.append((label, sym(mm.regs[7]), sym(r), (sym(mm.load(R_W + 0x78, 8)), mm.load(R_W + 0x80, 8))) +
                       ((tuple(mm.load(r + 8 * k, 8) for k in range(3)),) if label == "w740" else ()))
            junk_ret(mm, c[key])
        return f

    def ctx(mm):
        blk = mm.regs[6]
        rec.append(("ctx", sym(mm.regs[7]), sym(blk), tuple(sym(mm.load(blk + 8 * k, 8)) for k in range(4))))
        junk_ret(mm, c["ctx"])

    def drop_inner(mm):
        rec.append(("drop_inner", sym(mm.regs[7])))
        junk_ret(mm, 0)

    counters = {"name": 0, "sub": 0}
    sc = c["s"] if "s" in c else c

    def hdr(label):
        def f(mm):
            out = mm.regs[7]
            a = mm.regs[6]
            vec = mm.load(a, 8)
            rec.append((label, sym(out), sym(a), sym(mm.regs[2] & 0xffffffff), mm.load(a + 8, 4),
                        tuple(mm.load(vec + 8 * k, 8) for k in range(3))))
            mm.store(out, 8, sc["hdr"][0])
            mm.store(out + 8, 8, sc["hdr"][1])
            junk_ret(mm, 0)
        return f

    def name(mm):
        k = counters["name"] = counters["name"] + 1
        rec.append(("name", sym(mm.regs[7]), sym(mm.regs[6]), sym(mm.regs[2] & 0xffffffff)))
        junk_ret(mm, sc["names"][k - 1][0])
        mm.regs[2] = sc["names"][k - 1][1]

    def sub(mm):
        k = counters["sub"] = counters["sub"] + 1
        out, a = mm.regs[7], mm.regs[2]
        rec.append(("sub", sym(out), sym(mm.regs[6]), sym(a)))
        set_vec(mm, mm.load(a, 8), sc["vecs"][k - 1])
        set_vec(mm, out, sc["subs"][k - 1])
        junk_ret(mm, out)

    if fn == PRE:
        def conv(mm):
            rec.append(("convert", sym(mm.regs[7]), sym(mm.regs[6])))
            for k, v in enumerate(c["conv"]):
                mm.store(mm.regs[7] + 8 * k, 8, v)
            junk_ret(mm, 0)

        def look(mm):
            rec.append(("lookup", sym(mm.regs[7])))
            junk_ret(mm, c["look"])

        def exists(mm):
            rec.append(("exists", sym(mm.regs[7]), sym(mm.regs[6])))
            junk_ret(mm, c["ex"])

        def mkdir(mm):
            o = mm.regs[7]
            rec.append(("mkdir", sym(o), sym(mm.regs[6]), sym(mm.regs[2]), (mm.load(o, 4), mm.load(o + 4, 1))))
            junk_ret(mm, c["mk"])

        def wrap_err(mm):
            rec.append(("wrap_err", sym(mm.regs[7]), sym(mm.regs[6])))
            junk_ret(mm, c["wrapret"])

        stub(rel[SLOT["convert"]], conv)
        stub(rel[SLOT["lookup"]], look)
        stub(rel[SLOT["exists"]], exists)
        stub(rel[SLOT["mkdir"]], mkdir)
        stub(0x1500b90, wrap_err)
    if fn == CTXB:
        def fmt(mm):
            rec.append(("fmt", sym(mm.regs[7]), sym(mm.regs[6]), sym(mm.regs[2])))
            junk_ret(mm, 0)

        def wrap(mm):
            rec.append(("wrap", sym(mm.regs[7])))
            junk_ret(mm, c["wrapret"])

        def tail(mm):
            rec.append(("tail", sym(mm.regs[7]), sym(mm.regs[6])))
            junk_ret(mm, c["wrapret"])

        stub(rel[SLOT["format"]], fmt)
        stub(0x43030c0, wrap)
        stub(0x4303130, tail)
    stub(rel[SLOT["resolve"]], resolve)
    stub(rel[SLOT["alloc"]], alloc)
    stub(rel[SLOT["alloc_err"]], alloc_err)
    stub(rel[SLOT["dealloc"]], dealloc)
    stub(rel[SLOT["pre"]], pre)
    stub(rel[SLOT["write"]], write)
    if fn != CTXB:
        stub(STUB["ctx"], ctx)
    stub(STUB["drop_inner"], drop_inner)
    stub(STUB["hdr_plain"], hdr("hdr_plain"))
    stub(STUB["hdr_named"], hdr("hdr_named"))
    stub(STUB["name"], name)
    stub(STUB["sub"], sub)
    R_W = E + FRAME[WA]
    if fn in (WA, WB):
        stub(STUB["w670"], w_stub("w670", "w670"))
        stub(STUB["w740"], w_stub("w740", "w740"))
        stub(STUB["rmp_a"], rmp_a)
        stub(STUB["json_a"], text_ser)
        stub(STUB["json_b"], text_ser)


class EqTrace(mat.TraceMachine):
    """TraceMachine that notes the arguments of the real 0x159fca0 call as a trace row."""

    def __init__(self, image, code_override=None):
        super().__init__(image, code_override)
        self.rec = []

    SHL5 = {0x159fdb9: (9, bytes.fromhex("41c0e105")), 0x159fdd1: (10, bytes.fromhex("41c0e205"))}

    def step(self, va):
        if va in self.SHL5 and va not in self.override:
            reg, want = self.SHL5[va]
            if self.image.code(va, 4) != want:
                fail(f"shl r{reg}b, 5 moved at {va:#x}")
            self.regs[reg] = (self.regs[reg] & ~0xff) | ((self.regs[reg] << 5) & 0xff)
            return va + 4
        if va == EQ_NOCASE:
            self.rec.append(("eq_nocase", self.regs[6], self.regs[2], self.regs[1]))
        return super().step(va)


def run_case(m, fn, c):
    m.reset()
    rec = []
    m.rec = rec
    install(m, fn, c, rec)
    m.regions[0][2][:] = bytes([mat.STACK_FILL]) * len(m.regions[0][2])
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    out_words = vec_words = None
    if fn in (WA, WB):
        m.add_region(PATH_AT, REGION, c["path"])
        m.add_region(NORM_AT, REGION, c["norm"])
        m.regs[7], m.regs[6], m.regs[2], m.regs[1] = VALUE, PATH_AT, len(c["path"]), c["extra"]
    elif fn == PRE:
        m.add_region(PATH_AT, REGION, c["path"])
        m.regs[7], m.regs[6] = PATH_AT, len(c["path"])
    elif fn == CTXB:
        m.regs[7], m.regs[6], m.regs[2] = c["a"], c["b"], mat.JUNK
    elif fn in (E670, E740):
        m.add_region(ERR_AT, REGION, b"".join(v.to_bytes(8, "little") for v in c["err"]))
        m.regs[7], m.regs[6] = c["slot"], ERR_AT
    else:
        m.add_region(ARGS_AT, REGION, VEC_AT.to_bytes(8, "little") + bytes(3) + bytes([c["flag"]]) + bytes(0xec))
        m.add_region(VEC_AT, REGION, b"".join(v.to_bytes(8, "little") for v in c["vec0"]))
        m.add_region(OUT_AT, REGION, b"".join(v.to_bytes(8, "little") for v in c["out0"]))
        m.regs[7], m.regs[6], m.regs[2] = OUT_AT, VALUE, ARGS_AT
    try:
        m.run(fn, limit=6000)
    except NoReturn:
        return {"calls": rec, "ret": None, "regs_ok": True}
    got = {"calls": rec, "ret": m.regs[0],
           "regs_ok": [m.regs[k] for k in SAVED_REGS] == SAVED and m.regs[4] == E}
    if fn == SER:
        got["out"] = tuple(m.load(OUT_AT + 8 * k, 8) for k in range(3))
        got["vec"] = tuple(m.load(VEC_AT + 8 * k, 8) for k in range(3))
    return got


def expected(fn, c, mut=frozenset()):
    """(events, ret, out, vec) from the pure models."""
    if fn in (WA, WB):
        ev, ret = model_writer(c, fn, mut)
        return ev, ret, None, None
    if fn == PRE:
        return model_pre(c, mut) + (None, None)
    if fn == CTXB:
        return model_ctxb(c, mut) + (None, None)
    if fn in (E670, E740):
        c = dict(c, got=c["got"])
        ev, ret = model_wrap(c, fn == E670, mut)
        return ev, ret, None, None
    ev, out, vec = model_ser(c, FRAME[SER], ("args", 0), c["flag"] << 24, c["vec0"], mut)
    out = tuple(out[k] if out[k] is not None else c["out0"][k] for k in range(3))
    return ev, OUT_AT, out, vec if vec is not None else c["vec0"]


def compare(fn, want, got):
    ev, ret, out, vec = want
    if got["ret"] != ret and not (ret is None and got["ret"] is None):
        return False
    if not got["regs_ok"] or got["calls"] != ev:
        return False
    return fn != SER or (got["out"] == out and got["vec"] == vec)


def got_const(image, fn):
    if fn not in (E670, E740):
        return None
    slot = GOT_670 if fn == E670 else GOT_740
    return image.relative.get(slot, int.from_bytes(image.read(slot, 8), "little"))


def evaluate(image, fn, count, override=None, mut=frozenset(), stop_on_first=False, keep=None):
    m = EqTrace(image, override)
    bad = n = 0
    classes = {}
    const = got_const(image, fn)
    for i, c in enumerate(all_cases(fn, count)):
        if const is not None:
            c["got"] = const
        try:
            want = expected(fn, c, mut)
            got = run_case(m, fn, c)
            ok = compare(fn, want, got)
        except (ToolError, KeyError) as exc:
            got, ok = {"error": f"{type(exc).__name__}: {exc}", "calls": [], "ret": None}, False
        except Boundary as exc:
            got, ok = {"error": f"reached {exc.kind} stub", "calls": [], "ret": None}, False
        n += 1
        bad += not ok
        key = "error" if "error" in got else ">".join(r[0] for r in got["calls"] if r[0] not in ("dealloc", "eq_nocase")) or "early"
        classes[key] = classes.get(key, 0) + 1
        if keep is not None:
            keep(i, c, got, ok)
        if stop_on_first and not ok:
            break
    return n, bad, classes, m


# ---------------------------------------------------------------- static evidence
CHECKED = (
    (0x422ed6a, "48 83 fa 09", "writer A: whole-path length 9 for the /dev/null shortcut"),
    (0x422ed70, "48 b8 2f 64 65 76 2f 6e 75 6c", "writer A: immediate '/dev/nul' (little endian)"),
    (0x422ed82, "48 83 f1 6c", "writer A: ninth byte 'l'"),
    (0x422edac, "c6 44 24 48 06", "writer A: resolver request tag byte 6"),
    (0x422edb5, "66 c7 44 24 70 01 02", "writer A: request flags word 0x0201"),
    (0x422edcd, "80 3c 24 09", "writer A: resolver result tag 9"),
    (0x422ede1, "48 83 f8 02", "writer A: reject length-2 strings equal to .."),
    (0x422ede7, "66 81 39 2e 2e", "writer A: two-byte compare with 0x2e2e"),
    (0x422ee10, "80 79 fe 2e", "writer A: backward scan for '.'"),
    (0x422ee2f, "b9 03 00 00 00", "writer A: extension length argument 3"),
    (0x422ee5f, "c7 84 24 90 00 00 00 00 04 00 01", "writer A: binary options dword 0x1000400"),
    (0x422ee8c, "48 b8 00 00 00 00 00 00 00 80", "writer A: i64::MIN constant of the Ok marker"),
    (0x422ee96, "48 83 c8 04", "writer A: Ok marker is i64::MIN | 4"),
    (0x422eeae, "bf 80 00 00 00", "writer A: text buffer size 0x80"),
    (0x422eee9, "48 c7 44 24 48 02 00 00 00", "writer A: text options field 2"),
    (0x422ef21, "48 f7 d8", "writer A: neg cap, jo = cap == i64::MIN"),
    (0x422f06a, "49 33 07", "writer B: same /dev/null compare"),
    (0x422f172, "e8", "writer B: binary serializer call opcode"),
    (0x422f6bb, "48 83 f8 01", "wrap_boxed: tag 1 = nested error"),
    (0x422f6e6, "be 28 00 00 00", "wrap_boxed: box size 0x28"),
    (0x422f790, "b9 04 00 00 00", "wrap_inline: default class 4"),
    (0x422f795, "48 0f 48 ca", "wrap_inline: cmovs picks word0 ^ i64::MIN for negative words"),
    (0x422f79d, "48 83 fa 03", "wrap_inline: classes 1..3 own nothing"),
    (0x1502116, "c6 44 24 10 06", "precheck: resolver request tag byte 6"),
    (0x150211f, "66 c7 44 24 38 01 02", "precheck: request flags word 0x0201"),
    (0x1502139, "04 f9 3c 03", "precheck: result tags 7..9 (add 0xf9; cmp 3)"),
    (0x1502159, "83 3c 24 01", "precheck: converted record dword == 1 keeps the original path"),
    (0x1502182, "c7 44 24 40 ff 01 00 00", "precheck: directory mode 0x1ff"),
    (0x150218a, "c6 44 24 44 01", "precheck: recursive flag byte 1"),
    (0x43034f6, "f6 c2 01 75 21", "context builder: bit 0 of the second argument selects the tail call"),
    (0x38c20d0, "80 7a 0b 00", "struct3: options flag byte at +0xb == 0 selects the plain header"),
    (0x38c2125, "41 80 7e 0b 01", "struct3: flag byte == 1 emits field names"),
)

BYTE_MUTANTS = [   # (function, va, old, new, what); the twin B offset is +0x2f0
    (WA, 0x422ed6d, 0x09, 0x0a, "A: /dev/null length 9 -> 10"),
    (WA, 0x422ed9a, 0x2f, 0x2e, "A: abs byte '/' -> '.'"),
    (WA, 0x422edb0, 0x06, 0x05, "A: request tag 6 -> 5"),
    (WA, 0x422edba, 0x01, 0x03, "A: request flags low byte"),
    (WA, 0x422edbb, 0x02, 0x04, "A: request flags high byte"),
    (WA, 0x422ede4, 0x02, 0x03, "A: dotdot length 2 -> 3"),
    (WA, 0x422edea, 0x2e, 0x2d, "A: dotdot byte"),
    (WA, 0x422ee13, 0x2e, 0x2f, "A: scan byte '.' -> '/'"),
    (WA, 0x422ee30, 0x03, 0x04, "A: extension length 3 -> 4"),
    (WA, 0x422ee3b, 0x74, 0x75, "A: extension mismatch je -> jne"),
    (WA, 0x422ee41, 0x00, 0x01, "A: binary vec cap 0 -> 1"),
    (WA, 0x422ee4a, 0x01, 0x02, "A: binary vec ptr 1 -> 2"),
    (WA, 0x422ee69, 0x01, 0x00, "A: options flag byte 1 -> 0"),
    (WA, 0x422ee67, 0x04, 0x05, "A: options dword byte"),
    (WA, 0x422ee95, 0x80, 0x00, "A: MIN constant high byte"),
    (WA, 0x422ee99, 0x04, 0x05, "A: Ok marker | 4 -> | 5"),
    (WA, 0x422ee9e, 0x85, 0x84, "A: serializer Ok test jne -> je"),
    (WA, 0x422eeaf, 0x80, 0x81, "A: buffer size 0x80 -> 0x81"),
    (WA, 0x422eebd, 0x84, 0x85, "A: alloc null test je -> jne"),
    (WA, 0x422eec6, 0x80, 0x81, "A: initial cap 0x80 -> 0x81"),
    (WA, 0x422eeee, 0x02, 0x03, "A: text options field 2 -> 3"),
    (WA, 0x422eeff, 0x00, 0x01, "A: text options byte 0 -> 1"),
    (WA, 0x422ef13, 0x75, 0x74, "A: text error test jne -> je"),
    (WA, 0x422ef24, 0x70, 0x71, "A: cap niche jo -> jno"),
    (WA, 0x422ef3a, 0x75, 0x74, "A: precheck jne -> je"),
    (WA, 0x422ef54, 0x74, 0x75, "A: cap free test je -> jne"),
    (WA, 0x422ef83, 0x74, 0x75, "A: error-path cap test je -> jne"),
    (WA, 0x422efa5, 0x40, 0x38, "A: error word 1 slot"),
    (E670, 0x422f6be, 0x01, 0x02, "boxed: tag 1 -> 2"),
    (E670, 0x422f6bf, 0x74, 0x75, "boxed: tag 1 je -> jne"),
    (E670, 0x422f6c4, 0x75, 0x74, "boxed: tag 0 jne -> je"),
    (E670, 0x422f6e7, 0x28, 0x29, "boxed: box size 0x28 -> 0x29"),
    (E740, 0x422f791, 0x04, 0x03, "inline: default class 4 -> 3"),
    (E740, 0x422f797, 0x48, 0x49, "inline: cmovs -> cmovns"),
    (E740, 0x422f7a0, 0x03, 0x04, "inline: class window 3 -> 4"),
    (E740, 0x422f7a1, 0x73, 0x72, "inline: jae -> jb"),
    (E740, 0x422f7ae, 0x75, 0x74, "inline: class 0 jne -> je"),
    (E740, 0x422f7c4, 0x74, 0x75, "inline: word0 zero je -> jne"),
    (PRE, 0x150211a, 0x06, 0x05, "precheck: request tag 6 -> 5"),
    (PRE, 0x1502124, 0x01, 0x03, "precheck: flags low byte"),
    (PRE, 0x1502125, 0x02, 0x04, "precheck: flags high byte"),
    (PRE, 0x1502105, 0x2f, 0x2e, "precheck: abs byte '/' -> '.'"),
    (PRE, 0x1502100, 0x74, 0x75, "precheck: empty path je -> jne"),
    (PRE, 0x150213a, 0xf9, 0xfa, "precheck: tag window base"),
    (PRE, 0x150213c, 0x03, 0x04, "precheck: tag window width"),
    (PRE, 0x150213d, 0x73, 0x72, "precheck: window jae -> jb"),
    (PRE, 0x150214b, 0x74, 0x75, "precheck: lookup null je -> jne"),
    (PRE, 0x150215c, 0x01, 0x02, "precheck: converted dword compare 1 -> 2"),
    (PRE, 0x150215d, 0x74, 0x75, "precheck: converted je -> jne"),
    (PRE, 0x1502180, 0x75, 0x74, "precheck: exists jne -> je"),
    (PRE, 0x1502186, 0xff, 0xfe, "precheck: mode low byte"),
    (PRE, 0x1502187, 0x01, 0x02, "precheck: mode high byte"),
    (PRE, 0x150218e, 0x01, 0x00, "precheck: recursive flag 1 -> 0"),
    (PRE, 0x15021a3, 0x75, 0x74, "precheck: mkdir error jne -> je"),
    (CTXB, 0x43034f8, 0x01, 0x02, "context builder: bit test 1 -> 2"),
    (CTXB, 0x43034f9, 0x75, 0x74, "context builder: tail jne -> je"),
    (CTXB, 0x4303504, 0x08, 0x10, "context builder: buffer offset 8 -> 0x10"),
    (SER, 0x38c20d2, 0x0b, 0x0a, "struct3: flag byte offset 0xb -> 0xa"),
    (SER, 0x38c20d4, 0x74, 0x75, "struct3: flag zero je -> jne"),
    (SER, 0x38c20df, 0x03, 0x04, "struct3: header element count 3 -> 4"),
    (SER, 0x38c20f0, 0x02, 0x03, "struct3: header ok tag 2 -> 3"),
    (SER, 0x38c2129, 0x01, 0x02, "struct3: named flag 1 -> 2"),
    (SER, 0x38c2134, 0x0d, 0x0e, "struct3: first name length"),
    (SER, 0x38c2179, 0x0e, 0x0f, "struct3: second name length"),
    (SER, 0x38c21b5, 0x0c, 0x0d, "struct3: third name length"),
    (SER, 0x38c215e, 0x04, 0x05, "struct3: Ok marker | 4 -> | 5"),
    (SER, 0x38c218e, 0x10, 0x20, "struct3: second field offset 0x810 -> 0x820"),
    (SER, 0x38c21ca, 0x20, 0x30, "struct3: third field offset 0x1020 -> 0x1030"),
]


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
    info = {"binary_sha256": SHA256, "functions": {}, "checked_bytes": {}, "constants": {}}
    calls, decoded_all = [], {}
    rows = mat.fde_rows(image, list(ENDS))
    for fn in ENDS:
        lo, hi = rows[fn]
        if hi != ENDS[fn]:
            fail(f"FDE end of {fn:#x} moved")
        decoded = mat.sweep_padded(image, lo, hi)
        decoded_all[fn] = decoded
        callers = mat.caller_scan(image, fn)
        info["functions"][f"{fn:#x}"] = {"role": NAMEOF[fn], "fde_end": f"{hi:#x}", "fde_bytes": hi - lo,
                                         "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                                         "instructions": sum(1 for _, f in decoded if f is not None),
                                         "direct_callers": [f"{v:#x}" for v in callers[0]],
                                         "relative_addends": [f"{v:#x}" for v in callers[1]]}
        for va, kind, target in mat.call_sites(decoded, lo, hi):
            tgt = image.relative.get(target) if kind == "got" else target
            calls.append({"fn": NAMEOF[fn], "site": f"{va:#x}", "kind": kind, "slot": f"{target:#x}" if kind == "got" else "-",
                          "target": f"{tgt:#x}" if tgt is not None else "reg",
                          "role": HELPERS.get(tgt, "register call" if kind == "register" else "other"),
                          "slot_users": len(slot_users(image, target)) if kind == "got" else 0})
    for va, hx, what in CHECKED:
        want = bytes.fromhex(hx)
        if image.code(va, len(want)) != want:
            fail(f"expected bytes changed at {va:#x}")
        info["checked_bytes"][f"{va:#x}"] = {"bytes": want.hex(), "meaning": what}
    if image.read(EXT_AT, 3) != b"rmp":
        fail("extension constant is not rmp")
    info["constants"] = {"extension": {"va": f"{EXT_AT:#x}", "text": "rmp"}, "devnull": DEVNULL.decode(),
                         "text_options_tag": image.read(JSON_TAG_AT, 2).hex(),
                         "field_names": {f"{a:#x}": image.read(a, ln).hex() for a, ln in NAMES},
                         "helper_slots": {f"{s:#x}": f"{image.relative[s]:#x}" for s in SLOT.values()},
                         "context_template_prefix": image.read(FMT_AT, 8).hex()}
    return info, calls, decoded_all


# ---------------------------------------------------------------- controls
def controls(image):
    rows = []
    for fn in MODEL_MUTANTS:
        for name in MODEL_MUTANTS[fn]:
            n, bad, _, _ = evaluate(image, fn, 400, mut=frozenset([name]), stop_on_first=True)
            rows.append(("model", f"{NAMEOF[fn]}:{name}", int(bad > 0)))
    for fn, va, old, new, what in BYTE_MUTANTS:
        targets = [(fn, va)] + ([(WB, va + (WB - WA))] if fn == WA else [])
        for f2, v2 in targets:
            if image.code(v2, 1)[0] != old:
                fail(f"byte mutant at {v2:#x} does not start from {old:#04x}")
            n, bad, _, _ = evaluate(image, f2, 400, override={v2: new}, stop_on_first=True)
            rows.append(("code", f"{v2:#x}={new:#04x} {what}", int(bad > 0)))
    corrupt = bytearray(image.data)
    corrupt[image.text["offset"] + 7] ^= 1
    for label, fn in (("input", lambda: mat.Image(bytes(corrupt))),
                      ("input-range", lambda: image.code(image.text["address"] + image.text["size"] + 0x100, 4)),
                      ("extension-range", lambda: image.read(0x7fff_ffff_f000, 3))):
        try:
            fn()
            rows.append(("input", label, 0))
        except ToolError:
            rows.append(("input", label, 1))
    return rows


# ---------------------------------------------------------------- output
def describe(c, fn):
    if fn in (WA, WB):
        return f"{len(c['path'])}\t{c['norm'].hex()}\t{c['tag'] & 0xff}"
    if fn == PRE:
        return f"{len(c['path'])}\t{c['tag'] & 0xff}\t{int(c['look'] != 0)}{c['conv'][0] & 0xffffffff:x}"
    if fn == CTXB:
        return f"{c['b'] & 1}\t-\t-"
    if fn == SER:
        return f"{c['flag']}\t{c['hdr'][0]}\t{sum(1 for x in c['names'] if x[0] == 2)}{sum(1 for x in c['subs'] if x[0] == OKW)}"
    return f"{c['err'][0]:x}\t{c['err'][2] != 0}\t-"


def generate(out):
    image = mat.Image(BINARY.read_bytes())
    ev, call_rows, decoded = static_evidence(image)
    out.mkdir(parents=True, exist_ok=True)
    total = bad_total = 0
    class_lines = ["unit\ttrace_shape\tcases"]
    flow = ["unit\ttrace_shape\tstep\tevent"]
    instr = ["unit\taddress\tbytes\texecuted"]
    hit = [0, 0]
    with open(out / "cases.tsv", "w") as cf:
        cf.write("unit\tcase\ta\tb\tc\tclass\tcalls\trax\tmatch\n")
        for fn in ENDS:
            first = {}

            def keep(i, c, got, ok, fn=fn, first=first):
                shape = "error" if "error" in got else ">".join(r[0] for r in got["calls"] if r[0] not in ("dealloc", "eq_nocase")) \
                    or "early"
                ret = got.get("ret")
                cf.write(f"{NAMEOF[fn]}\t{i}\t{describe(c, fn)}\t{shape}\t{len(got['calls'])}\t"
                         f"{'noreturn' if ret is None else format(ret, 'x')}\t{'yes' if ok else 'NO'}\n")
                if shape not in first:
                    first[shape] = got["calls"]

            n, bad, classes, m = evaluate(image, fn, PER_UNIT[fn], keep=keep)
            total += n
            bad_total += bad
            for k in sorted(classes):
                class_lines.append(f"{NAMEOF[fn]}\t{k}\t{classes[k]}")
            for shape in sorted(first):
                for k, row in enumerate(first[shape]):
                    flow.append(f"{NAMEOF[fn]}\t{shape}\t{k}\t{row}")
            for va, f in decoded[fn]:
                if f is None:
                    continue
                run = int(va in m.seen)
                instr.append(f"{NAMEOF[fn]}\t{va:#x}\t{f['bytes'].hex()}\t{run}")
                hit[0] += run
                hit[1] += 1
    (out / "outcome-classes.tsv").write_text("\n".join(class_lines) + "\n")
    (out / "flow.tsv").write_text("\n".join(flow) + "\n")
    (out / "instructions.tsv").write_text("\n".join(instr) + "\n")
    (out / "calls.tsv").write_text(
        "fn\tsite\tkind\tslot\ttarget\trole\tslot_users\n"
        + "".join("\t".join(str(r[k]) for k in ("fn", "site", "kind", "slot", "target", "role", "slot_users")) + "\n"
                  for r in call_rows))
    (out / "constants.json").write_text(json.dumps(ev, indent=2, sort_keys=True) + "\n")
    ctl = controls(image)
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    summary = {"binary_sha256": SHA256, "cases": total, "mismatches": bad_total, "instructions_executed": hit[0],
               "instructions_total": hit[1],
               "negative_controls": {"total": len(ctl), "detected": sum(r[2] for r in ctl)}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps(
        {"cases": total, "negative_controls": len(ctl), "negative_detected": sum(r[2] for r in ctl)}, sort_keys=True) + "\n")
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
