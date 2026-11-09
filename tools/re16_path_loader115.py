#!/usr/bin/env python3
"""Reconstruct and validate the node #115 extension-dispatched loader 0x422e410 (called "lookup" by the RE-016 state-load chain).

Observed contract (all from machine code, role names are inferences):
  loader(rdi = name ptr, rsi = name len, rdx = ignored) -> (rax = 0 | 1, rdx = value | error)
  1. clone the (ptr, len) string with 0x1500c10 into a (cap, ptr, len) owner;
  2. 0x1500d20 judges the clone: false -> format a message (0x141e3a0 with the template at 0x43b857) and wrap it with 0x43030c0,
     return (1, wrapped);
  3. is_abs = len != 0 && first byte == '/'; 0x5cab560 resolves the clone with a 0x26-byte request {ptr, len, tag 6,
     flags 0x0201, is_abs}; result tag 9 carries a (ptr, len) string, any other tag skips the extension test;
  4. extension test on that string: len == 2 && ".." is rejected, otherwise scan backwards for the last '.', a '.' at index 0 is
     rejected (hidden file), the extension (bytes after the dot) must be 3 bytes and equal "rmp" ignoring ASCII case
     (0x159fca0 with rcx = 3, rdx = 0x7c95c0);
  5. "rmp" branch: 0x5ca4d50 loads the clone; word0 == i64::MIN (the `neg; jno` test) is the error arm 0x422ecc0, otherwise
     0x3266520 decodes it (tag 9 = ok value, else error 0x422eac0);
     other branch: 0x5ca4940 loads the clone; same error test with the arm 0x422eb70, otherwise 0x3ef18b0 decodes it
     (rax == 1 = error 0x422ebf0, else ok value rdx);
  6. every path frees the loaded buffer when its word0 != 0 and finally the clone when cap != 0; error arms return rax = 1.
The tool runs the real machine code with the concrete x86-64 evaluator of tools/re16_state_materialize115.py (the extension
comparison 0x159fca0 is real code; imports and the other callees are stubs that scramble caller-saved registers) and compares
every case with the pure-Python `model()` including the call trace.  The binary is never executed.
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
    if form["op"] == 0xc7 and form["p66"]:
        at = form["len"] - 4
        form["imm"] = struct.unpack_from("<h", code, at)[0]
        form["len"] = at + 2
        form["bytes"] = bytes(code[:form["len"]])
    elif form["op"] == 0x81 and form["p66"]:
        at = form["len"] - 4
        form["imm"] = struct.unpack_from("<h", code, at)[0]
        form["len"] = at + 2
        form["bytes"] = bytes(code[:form["len"]])
    return form


mat.decode = decode16

LOOKUP, LOOKUP_END = 0x422e410, 0x422e730
CLONE_SLOT, VALID_SLOT, RESOLVE_SLOT = 0x64e0948, 0x64e0950, 0x64e0938
RMP_LOAD_SLOT, OTHER_LOAD_SLOT, FMT_SLOT, DEALLOC_SLOT = 0x64e09b8, 0x64e09c0, 0x64df6e8, 0x64df4a0
EQ_NOCASE, WRAP = 0x159fca0, 0x43030c0
RMP_ERR, OTHER_ERR, OTHER_DECODE_ERR, RMP_DECODE_ERR = 0x422ecc0, 0x422eb70, 0x422ebf0, 0x422eac0
OTHER_DECODE, RMP_DECODE = 0x3ef18b0, 0x3266520
EXT_AT, TEMPLATE_AT = 0x7c95c0, 0x43b857
MIN64 = 1 << 63
E = mat.ENTRY_SP
R = E - 0xf0               # body rsp: return address + four pushes + 0xc8
NAME_AT, PATH_AT, NORM_AT = 0x7d00_0100_0000, 0x7d00_0200_0000, 0x7d00_0300_0000
REGION = 0x100
CASES = 14000
SAVED_REGS, SAVED = mat.SAVED_REGS, mat.SAVED
HELPERS = {EQ_NOCASE: "eq_ignore_ascii_case", WRAP: "wrap_error", RMP_ERR: "rmp_load_error", OTHER_ERR: "other_load_error",
           OTHER_DECODE_ERR: "other_decode_error", RMP_DECODE_ERR: "rmp_decode_error", OTHER_DECODE: "other_decode",
           RMP_DECODE: "rmp_decode", 0x1500c10: "clone", 0x1500d20: "valid", 0x5cab560: "resolve", 0x5ca4d50: "rmp_load",
           0x5ca4940: "other_load", 0x141e3a0: "format", 0x635de30: "dealloc", 0x63f0a50: "_Unwind_Resume"}


def S(off):
    return ("stack", off)


def sym(v):
    for base, tag in ((NAME_AT, "name"), (PATH_AT, "clone"), (NORM_AT, "norm")):
        if base <= v < base + REGION:
            return (tag, v - base)
    if mat.STACK_TOP - 0x10000 <= v < mat.STACK_TOP:
        return ("stack", v - R)
    return ("abs", v)


# ---------------------------------------------------------------- cases
def rnd(s):
    return int.from_bytes(s.take(8), "little")


EXTS = (b"rmp", b"RMP", b"rMp", b"Rmp", b"rmP", b"rm", b"rmpx", b"xrmp", b"json", b"", b"r.p", b"rmq", b"smp", b"rnp", b"rmo",
        b"jsn", b"toml", b"Rm", b"rmp ", b"mp")
STEMS = (b"state", b"a", b"x/y", b"/abs/state", b"dir.d/f", b"", b"..", b".", b"...", b"a.b", b"a.rmp", b"a.json", b"./s",
         b"../s", b".hid")
TAGS = (9, 9, 9, 9, 0, 1, 6, 8, 10, 0x109)


def pick_norm(s):
    k = s.below(8)
    if k == 0:
        return s.pick((b"..", b".", b"", b"...", b".rmp", b".RMP", b"a.", b"a..", b"x.rmp.", b"..rmp", b"a.rmp.rmp"))
    if k == 1:
        return s.pick(STEMS) + b"." + s.pick(EXTS)
    if k == 2:
        return s.pick(STEMS) + s.pick(EXTS)
    if k == 3:
        return bytes(s.pick(b"abc./rmpRMP") for _ in range(s.below(9)))
    return s.pick(STEMS) + b"." + s.pick(EXTS)


def make_case(s, idx):
    pick = idx % 12
    path = s.pick((b"/node/state.rmp", b"state.rmp", b"", b"/", b"/x", b"rel/s.json", b"\xff/a", b"a"))
    if s.below(3) == 0:
        path = bytes(s.take(s.below(20)))
    c = {"idx": idx, "path": path, "cap": rnd(s) >> s.below(64), "valid": s.below(8) != 0 if pick != 3 else False,
         "tag": s.pick(TAGS) if pick != 4 else 9, "norm": pick_norm(s)}
    if pick in (5, 6):
        c["norm"] = s.pick(STEMS) + b"." + s.pick((b"rmp", b"RMP", b"rMp"))
        c["tag"] = 9
    if pick == 7:
        c["norm"] = s.pick(STEMS) + b"." + s.pick((b"json", b"rm", b"rmpx", b"xrmp", b""))
        c["tag"] = 9
    r12 = rnd(s) >> s.below(64) if s.below(3) else s.pick((0, 1, MIN64, MIN64 - 1, MIN64 + 1, M64))
    if pick in (8, 9):
        r12 = MIN64
    if pick in (10, 11):
        r12 = s.pick((0, 0, 1, 0x40))
    c["w"] = [r12, rnd(s), rnd(s)]
    c["dec"] = [s.pick((0, 1, 2, 5)) if s.below(2) else rnd(s), rnd(s)]        # 0x3ef18b0 rax, rdx
    c["rd"] = [(s.pick((9, 9, 0, 3, 0x109)) | (rnd(s) << 8)) & M64, rnd(s), rnd(s), rnd(s)]  # 0x3266520 out words
    c["err"] = [rnd(s) for _ in range(6)]   # wrap, rmp_err, other_err, other_dec_err, rmp_dec_err, fmt
    c["abs_len"] = len(path)
    return c


def all_cases(count=CASES):
    s = mat.Stream("re16-path-loader-115")
    for k in range(count):
        yield make_case(s, k)


# ---------------------------------------------------------------- reconstruction
def ext_of(norm, mut=frozenset()):
    """Extension rule of steps 4: returns the 3-byte-compare candidate or None when the string is rejected."""
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


def eq_nocase(a, b, mut=frozenset()):
    if len(a) != len(b):
        return False
    if "case_sensitive" in mut:
        return a == b
    return a.lower() == b.lower()


def model(c, mut=frozenset()):
    """Pure reconstruction: (calls, return rax, return rdx)."""
    path = c["path"]
    n = len(path)
    calls = [("clone", S(8), ("name", 0), n)]
    p1 = ("clone", 0)
    done_free_clone = [("dealloc", p1, c["cap"], 0)] if c["cap"] else []
    if not c["valid"] and "valid_inverted" not in mut or c["valid"] and "valid_inverted" in mut:
        calls.append(("valid", p1, n))
        calls.append(("format", S(0xb0), TEMPLATE_AT, S(0x20), ("args", S(8), 0x41d5360, 0x446b15, S(0x68), S(0xa0), 0x41ca900)))
        calls.append(("wrap", S(0xb0)))
        return calls + done_free_clone, 1, c["err"][0]
    calls.append(("valid", p1, n))
    is_abs = int(n != 0 and path[0] == 0x2f) if "abs_always" not in mut else 1
    calls.append(("resolve", S(0x68), S(0x20), ("req", p1[0], n, 6, 0x0201, is_abs)))
    ntag, norm = c["tag"] & 0xff, c["norm"]
    rmp = False
    if ntag == 9:
        calls_ext = ext_of(norm, mut)
        if calls_ext is not None:
            calls.append(("eq_nocase", len(calls_ext), EXT_AT, 3))
            rmp = len(calls_ext) == 3 and eq_nocase(calls_ext, b"rmp", mut)
    if "rmp_swapped" in mut:
        rmp = not rmp
    r12, r15, w2 = c["w"]
    if rmp:
        calls.append(("rmp_load", S(0x20), p1, n))
        if r12 == MIN64 and "min_ignored" not in mut:
            calls.append(("rmp_err", S(8), r15))
            return calls + done_free_clone, 1, c["err"][1]
        calls.append(("rmp_decode", S(0x68), S(0x20), 0, (r15, w2, r15, w2, 1, 0x20, 0)))
        free = [("dealloc", ("abs", r15), r12, 0)] if r12 else []
        if c["rd"][0] & 0xff == 9:
            return calls + free + done_free_clone, 0, c["rd"][1]
        calls.append(("rmp_decode_error", S(8), tuple(c["rd"])))
        return calls + free + done_free_clone, 1, c["err"][4]
    calls.append(("other_load", S(0x20), p1, n))
    if r12 == MIN64 and "min_ignored" not in mut:
        calls.append(("other_err", S(8), r15))
        return calls + done_free_clone, 1, c["err"][2]
    calls.append(("other_decode", S(0x20), (r15, w2, 0, 0, r15, w2)))
    free = [("dealloc", ("abs", r15), r12, 0)] if r12 else []
    if c["dec"][0] == 1:
        calls.append(("other_decode_error", S(8), c["dec"][1]))
        return calls + free + done_free_clone, 1, c["err"][3]
    return calls + free + done_free_clone, 0, c["dec"][1]


MODEL_MUTANTS = ["no_dotdot", "dot_char", "hidden_ok", "case_sensitive", "valid_inverted", "abs_always", "rmp_swapped",
                 "min_ignored"]


# ---------------------------------------------------------------- harness
def clobber(mm, ret):
    mat.clobber(mm, ret)


def install(m, c, rec):
    img = m.image
    rel = img.relative

    def stub(target, fn):
        m.stubs[target] = fn

    def clone(mm):
        dst, src, size = mm.regs[7], mm.regs[6], mm.regs[2]
        rec.append(("clone", sym(dst), sym(src), size))
        mm.store(dst, 8, c["cap"])
        mm.store(dst + 8, 8, PATH_AT)
        mm.store(dst + 16, 8, size)
        clobber(mm, dst)

    def valid(mm):
        rec.append(("valid", sym(mm.regs[7]), mm.regs[6]))
        clobber(mm, int(c["valid"]) | (rnd_junk << 8))

    def fmt(mm):
        a = mm.regs[2]
        rec.append(("format", sym(mm.regs[7]), mm.regs[6], sym(a),
                    ("args", sym(mm.load(R + 0x68, 8)), mm.load(R + 0x70, 8), mm.load(R + 0xa0, 8), sym(mm.load(R + 0xa8, 8)),
                     sym(mm.load(a, 8)), mm.load(a + 8, 8))))
        clobber(mm, 0)

    def wrap(mm):
        rec.append(("wrap", sym(mm.regs[7])))
        clobber(mm, c["err"][0])

    def resolve(mm):
        out, req = mm.regs[7], mm.regs[6]
        rec.append(("resolve", sym(out), sym(req),
                    ("req", sym(mm.load(req, 8))[0], mm.load(req + 8, 8), mm.load(req + 0x10, 1), mm.load(req + 0x38, 2),
                     mm.load(req + 0x3a, 1))))
        mm.store(out, 8, c["tag"])
        mm.store(out + 8, 8, NORM_AT)
        mm.store(out + 16, 8, len(c["norm"]))
        clobber(mm, out)

    def load_stub(label):
        def fn(mm):
            out = mm.regs[7]
            rec.append((label, sym(out), sym(mm.regs[6]), mm.regs[2]))
            for k, v in enumerate(c["w"]):
                mm.store(out + 8 * k, 8, v)
            clobber(mm, out)
        return fn

    def err(label, idx):
        def fn(mm):
            rec.append((label, sym(mm.regs[7]), mm.regs[6]))
            clobber(mm, c["err"][idx])
        return fn

    def other_decode(mm):
        a = mm.regs[7]
        rec.append(("other_decode", sym(a), tuple(mm.load(a + k, 8) for k in (0, 8, 0x10, 0x18, 0x20, 0x28))))
        clobber(mm, c["dec"][0])
        mm.regs[2] = c["dec"][1]

    def rmp_decode(mm):
        out, a = mm.regs[7], mm.regs[6]
        rec.append(("rmp_decode", sym(out), sym(a), mm.regs[2] & 0xffffffff,
                    (mm.load(a, 8), mm.load(a + 8, 8), mm.load(a + 0x10, 8), mm.load(a + 0x18, 8), mm.load(a + 0x20, 1),
                     mm.load(a + 0x22, 2), mm.load(a + 0x24, 1))))
        for k, v in enumerate(c["rd"]):
            mm.store(out + 8 * k, 8, v)
        clobber(mm, out)

    def rmp_decode_error(mm):
        a = mm.regs[6]
        rec.append(("rmp_decode_error", sym(mm.regs[7]), tuple(mm.load(a + 8 * k, 8) for k in range(4))))
        clobber(mm, c["err"][4])

    def dealloc(mm):
        rec.append(("dealloc", sym(mm.regs[7]), mm.regs[6], mm.regs[2]))
        clobber(mm, 0)

    rnd_junk = c["tag"] >> 8
    stub(rel[CLONE_SLOT], clone)
    stub(rel[VALID_SLOT], valid)
    stub(rel[RESOLVE_SLOT], resolve)
    stub(rel[RMP_LOAD_SLOT], load_stub("rmp_load"))
    stub(rel[OTHER_LOAD_SLOT], load_stub("other_load"))
    stub(rel[FMT_SLOT], fmt)
    stub(rel[DEALLOC_SLOT], dealloc)
    stub(WRAP, wrap)
    stub(RMP_ERR, err("rmp_err", 1))
    stub(OTHER_ERR, err("other_err", 2))
    stub(OTHER_DECODE_ERR, err("other_decode_error", 3))
    stub(RMP_DECODE_ERR, rmp_decode_error)
    stub(OTHER_DECODE, other_decode)
    stub(RMP_DECODE, rmp_decode)


def run_case(m, c):
    m.reset()
    rec = []
    install(m, c, rec)
    m.regions[0][2][:] = bytes([mat.STACK_FILL]) * len(m.regions[0][2])
    m.add_region(NAME_AT, REGION, c["path"])
    m.add_region(PATH_AT, REGION, c["path"])
    m.add_region(NORM_AT, REGION, c["norm"])
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2] = NAME_AT, len(c["path"]), 0x64767a8
    # the eq_ignore_ascii_case call is real code: trace it
    orig = m.stubs
    m.run(LOOKUP, limit=4000)
    regs_ok = [m.regs[k] for k in SAVED_REGS] == SAVED and m.regs[4] == E
    return {"calls": rec, "ret": (m.regs[0], m.regs[2]), "regs_ok": regs_ok}


class EqTrace(mat.TraceMachine):
    """TraceMachine that notes the arguments of the real 0x159fca0 call as a trace row."""

    def __init__(self, image, code_override=None):
        super().__init__(image, code_override)
        self.eq_rows = []

    SHL5 = {0x159fdb9: (9, bytes.fromhex("41c0e105")), 0x159fdd1: (10, bytes.fromhex("41c0e205"))}

    def step(self, va):
        if va in self.SHL5 and va not in self.override:
            reg, want = self.SHL5[va]
            if self.image.code(va, 4) != want:
                fail(f"shl r{reg}b, 5 moved at {va:#x}")
            self.regs[reg] = (self.regs[reg] & ~0xff) | ((self.regs[reg] << 5) & 0xff)   # 8-bit shl by 5; the next or sets the flags
            return va + 4
        if va == EQ_NOCASE:
            self.eq_rows.append(("eq_nocase", self.regs[6], self.regs[2], self.regs[1]))
        return super().step(va)


def compare(want, got):
    calls_w, rax, rdx = want
    calls_g = []
    for row in got["calls"]:
        calls_g.append(row)
    return got["regs_ok"] and got["ret"] == (rax, rdx) and got["calls"] == calls_w


def merge_eq(m, got):
    """Insert the traced eq rows after the matching resolve row so the trace is in program order."""
    rows = list(got["calls"])
    for k, row in enumerate(rows):
        if row[0] == "resolve" and m.eq_rows:
            rows.insert(k + 1, m.eq_rows[0])
            break
    got["calls"] = rows


def evaluate(image, cases, override=None, mut=frozenset(), stop_on_first=False, keep=None):
    m = EqTrace(image, override)
    bad = n = 0
    classes = {}
    for i, c in enumerate(cases):
        want = model(c, mut)
        try:
            m.eq_rows = []
            got = run_case(m, c)
            merge_eq(m, got)
            ok = compare(want, got)
        except (ToolError, KeyError) as exc:
            got, ok = {"error": f"{type(exc).__name__}: {exc}", "calls": [], "ret": None}, False
        except Boundary as exc:
            got, ok = {"error": f"reached {exc.kind} stub", "calls": [], "ret": None}, False
        n += 1
        bad += not ok
        names = [r[0] for r in got["calls"]]
        key = ("error" if "error" in got else ("rmp" if "rmp_load" in names else "other" if "other_load" in names else "early"))
        if "error" not in got:
            key += "/" + ("err" if got["ret"][0] == 1 else "ok")
        classes[key] = classes.get(key, 0) + 1
        if keep is not None:
            keep(i, c, got, ok)
        if stop_on_first and not ok:
            break
    return n, bad, classes, m


# ---------------------------------------------------------------- static evidence
CHECKED = (
    (0x422e451, "80 3b 2f", "is_abs test: first byte == '/'"),
    (0x422e4d7, "c6 44 24 30 06", "resolve request tag byte = 6"),
    (0x422e4dc, "88 44 24 5a", "resolve request is_abs byte at +0x3a"),
    (0x422e4e0, "66 c7 44 24 58 01 02", "resolve request flags word 0x0201"),
    (0x422e4f7, "80 7c 24 68 09", "resolve result tag 9 = ok string"),
    (0x422e50c, "48 83 f8 02", "reject length-2 strings equal to .."),
    (0x422e512, "66 81 39 2e 2e", "compare the two bytes with 0x2e2e"),
    (0x422e53c, "80 79 fe 2e", "backward scan for '.'"),
    (0x422e545, "48 85 f6", "dot at index 0 is rejected"),
    (0x422e557, "b9 03 00 00 00", "extension length argument 3"),
    (0x422e58a, "0f 81", "rmp branch: jno = word0 != i64::MIN"),
    (0x422e5c4, "71", "other branch: jno = word0 != i64::MIN"),
    (0x422e636, "48 83 f8 01", "other decode: rax == 1 is the error arm"),
    (0x422e6af, "80 7c 24 68 09", "rmp decode: tag 9 is the ok value"),
)

BYTE_MUTANTS = [
    (0x422e453, 0x2f, 0x2e, "abs byte '/' -> '.'"),
    (0x422e4db, 0x06, 0x05, "request tag 6 -> 5"),
    (0x422e4e5, 0x01, 0x03, "request flags 0x0201 -> 0x0203"),
    (0x422e4e6, 0x02, 0x04, "request flags 0x0201 -> 0x0401"),
    (0x422e4fb, 0x09, 0x08, "resolve ok tag 9 -> 8"),
    (0x422e50f, 0x02, 0x03, "dotdot length 2 -> 3"),
    (0x422e515, 0x2e, 0x2d, "dotdot byte 0x2e -> 0x2d"),
    (0x422e516, 0x2e, 0x2d, "dotdot second byte 0x2e -> 0x2d"),
    (0x422e53f, 0x2e, 0x2f, "scan byte '.' -> '/'"),
    (0x422e558, 0x03, 0x04, "extension length 3 -> 4"),
    (0x422e533, 0x74, 0x75, "empty scan je -> jne"),
    (0x422e548, 0x74, 0x75, "hidden file je -> jne"),
    (0x422e563, 0x74, 0x75, "extension mismatch je -> jne"),
    (0x422e58b, 0x81, 0x80, "rmp error test jno -> jo"),
    (0x422e5c4, 0x71, 0x70, "other error test jno -> jo"),
    (0x422e639, 0x01, 0x02, "other decode error rax==1 -> 2"),
    (0x422e6b3, 0x09, 0x08, "rmp decode ok tag 9 -> 8"),
    (0x422e44a, 0x74, 0x75, "valid test je -> jne"),
    (0x422e44f, 0x74, 0x75, "empty-string abs test je -> jne"),
    (0x422e4fd, 0x85, 0x84, "resolve tag jne -> je"),
    (0x422e5d8, 0x01, 0x00, "error return 1 -> 0"),
    (0x422e64e, 0x01, 0x00, "decode error return 1 -> 0"),
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
    rows = mat.fde_rows(image, [LOOKUP])
    lo, hi = rows[LOOKUP]
    decoded = mat.sweep_padded(image, lo, hi)
    calls = []
    for va, kind, target in mat.call_sites(decoded, lo, hi):
        tgt = image.relative.get(target) if kind == "got" else target
        calls.append({"site": f"{va:#x}", "kind": kind, "slot": f"{target:#x}" if kind == "got" else "-",
                      "target": f"{tgt:#x}" if tgt is not None else "reg",
                      "role": HELPERS.get(tgt, "register call" if kind == "register" else "other"),
                      "slot_users": len(slot_users(image, target)) if kind == "got" else 0})
    checks = {}
    for va, hx, what in CHECKED:
        want = bytes.fromhex(hx)
        if image.code(va, len(want)) != want:
            fail(f"expected bytes changed at {va:#x}")
        checks[f"{va:#x}"] = {"bytes": want.hex(), "meaning": what}
    ext = image.read(EXT_AT, 3)
    if ext != b"rmp":
        fail("extension constant is not rmp")
    callers = mat.caller_scan(image, LOOKUP)
    if image.relative.get(0x64e9628) is None:
        fail("boundary slot missing")
    info = {"binary_sha256": SHA256,
            "function": {"start": f"{lo:#x}", "fde_end": f"{hi:#x}", "fde_bytes": hi - lo,
                         "sha256": hashlib.sha256(image.code(lo, hi - lo)).hexdigest(),
                         "instructions": sum(1 for _, fm in decoded if fm is not None)},
            "extension_constant": {"va": f"{EXT_AT:#x}", "bytes": ext.hex(), "text": ext.decode()},
            "template_prefix": image.read(TEMPLATE_AT, 8).hex(),
            "helper_slots": {f"{s:#x}": f"{image.relative[s]:#x}" for s in (
                CLONE_SLOT, VALID_SLOT, RESOLVE_SLOT, RMP_LOAD_SLOT, OTHER_LOAD_SLOT, FMT_SLOT, DEALLOC_SLOT)},
            "direct_callers": [f"{v:#x}" for v in callers[0]], "relative_addends": [f"{v:#x}" for v in callers[1]],
            "checked_bytes": checks, "frame": {"body_rsp_from_entry": R - E}}
    return info, calls, decoded


# ---------------------------------------------------------------- controls
def controls(image, cases):
    rows = []
    for name in MODEL_MUTANTS:
        n, bad, _, _ = evaluate(image, cases, mut=frozenset([name]), stop_on_first=True)
        rows.append(("model", name, int(bad > 0)))
    for va, old, new, what in BYTE_MUTANTS:
        if image.code(va, 1)[0] != old:
            fail(f"byte mutant at {va:#x} does not start from {old:#04x}")
        n, bad, _, _ = evaluate(image, cases, override={va: new}, stop_on_first=True)
        rows.append(("code", f"{va:#x}={new:#04x} {what}", int(bad > 0)))
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
def generate(out):
    image = mat.Image(BINARY.read_bytes())
    ev, call_rows, decoded = static_evidence(image)
    out.mkdir(parents=True, exist_ok=True)
    case_lines = ["case\tpath_len\tnorm\ttag\toutcome\tcalls\trax\tmatch"]
    first = {}
    sample = [0]

    def keep(i, c, got, ok):
        if True:
            outcome = "error" if "error" in got else "|".join(r[0] for r in got["calls"] if r[0] in (
                "rmp_load", "other_load", "format", "eq_nocase"))
            case_lines.append(f"{i}\t{len(c['path'])}\t{c['norm'].hex()}\t{c['tag'] & 0xff}\t{outcome or 'early'}\t"
                              f"{len(got['calls'])}\t{got['ret'][0] if got.get('ret') else '-'}\t{'yes' if ok else 'NO'}")
        key = (tuple(r[0] for r in got["calls"]), got["ret"][0] if got.get("ret") else None)
        if key not in first:
            first[key] = got["calls"]

    n, bad, classes, m = evaluate(image, all_cases(), keep=keep)
    (out / "cases.tsv").write_text("\n".join(case_lines) + "\n")
    (out / "outcome-classes.tsv").write_text(
        "outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    flow = ["trace_shape\trax\tstep\tevent"]
    for key in sorted(first, key=lambda k: (k[1] is None, k[1] or 0, k[0])):
        for k, row in enumerate(first[key]):
            flow.append(f"{'>'.join(key[0])}\t{key[1]}\t{k}\t{row}")
    (out / "flow.tsv").write_text("\n".join(flow) + "\n")
    (out / "calls.tsv").write_text(
        "site\tkind\tslot\ttarget\trole\tslot_users\n"
        + "".join("\t".join(str(r[k]) for k in ("site", "kind", "slot", "target", "role", "slot_users")) + "\n"
                  for r in call_rows))
    lines = ["address\tbytes\texecuted"]
    hit = [0, 0]
    for va, f in decoded:
        if f is None:
            continue
        run = int(va in m.seen)
        lines.append(f"{va:#x}\t{f['bytes'].hex()}\t{run}")
        hit[0] += run
        hit[1] += 1
    (out / "instructions.tsv").write_text("\n".join(lines) + "\n")
    (out / "constants.json").write_text(json.dumps(ev, indent=2, sort_keys=True) + "\n")
    ctl = controls(image, [c for _, c in zip(range(300), all_cases())])
    (out / "negative-controls.tsv").write_text(
        "kind\tcontrol\tdetected\n" + "".join("\t".join(str(x) for x in r) + "\n" for r in ctl))
    summary = {"binary_sha256": SHA256, "cases": n, "mismatches": bad, "instructions_executed": hit[0],
               "instructions_total": hit[1], "outcome_classes": len(classes),
               "negative_controls": {"total": len(ctl), "detected": sum(r[2] for r in ctl)}}
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
