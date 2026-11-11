"""Reconstruct and verify three state-export file writers of node #115: the nil writer 0x50de300, the three-field
struct writer 0x50de520 and the generic data writer 0x1740650.

All three share one front.  A path equal to "/dev/null" is a no-op (result 0).  Otherwise the last path component is
taken with Path::components().next_back(); a Normal component that is not ".." and whose text after its last dot (a
dot at index 0 does not count) equals "rmp" ignoring ASCII case selects the msgpack encoding; every other path selects
pretty JSON.  The encoded bytes are held in a heap buffer, the parent directory is ensured through the slot 0x64e0028
and, only if that returns 0, the bytes are written through the slot 0x64e09e8 together with the caller's extra
argument.  The buffer is freed at the end and the result of the last step is returned.

The nil writer stores the single byte 0xc0 (msgpack nil, from a one-byte allocation made with the try-allocate routine
0x5963650) or the four bytes "null" (a 0x80-byte malloc).  The struct writer serializes a three-field object through
the msgpack driver 0x50da6c0 or, for JSON, inline: "{", three keys written by the real serde_json key writer 0x510d230
with ": " after each key, values from 0x50a44d0 / 0x50472b0, then "\\n", depth-1 indents and "}".  The data writer drives
the msgpack serializer 0x175ef30 or the JSON serializer 0x175cc70 with an empty 0x80-byte buffer.  Every failure
path (allocation, serializer error, depth underflow) is reconstructed, including which error constructor receives
which record.

`model_*` is the reconstruction.  A concrete x86-64 evaluator runs the real bytes of the three bodies, the real key
writer 0x510d230 and the real ASCII-case compare 0x159fca0 on generated cases against a shared callee environment,
and compares the result, every callee call (arguments and buffer bytes), frees and the panic kind.  The binary is
never executed.
"""
import argparse
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import rmp_map_pairs_115 as rm  # noqa: E402

BINARY = rm.BINARY
SHA256 = rm.SHA256
ToolError = rm.ToolError
Boundary = rm.Boundary
fail = rm.fail
M64 = rm.M64
OK_TRIPLE = rm.OK_TRIPLE
ERR_TAG = rm.ERR_TAG

NIL, STRUCT, DATA = 0x50de300, 0x50de520, 0x1740650
BODIES = {"nil": NIL, "struct": STRUCT, "data": DATA}
KEYWRITER, EXTCMP = 0x510d230, 0x159fca0
REALS = {"keywriter": KEYWRITER, "extcmp": EXTCMP, "grow": 0x5963a10, "finish_grow": 0x5963650}

# Callee targets (direct calls) and import slots, each verified against the bytes by `static_rows`.
RESERVE, TRY_ALLOC, ESCAPE = 0x5963a10, 0x5963650, 0x50a3510
G_REALLOC, G_ALIGNED_REALLOC, G_ALIGNED_ALLOC = 0x64df588, 0x64df580, 0x64df590
RMP_STRUCT, VALUE_A, VALUE_B = 0x50da6c0, 0x50a44d0, 0x50472b0
ERR_SLOT_N, ERR_SLOT_S = 0x50df400, 0x50df4c0
RMP_DATA, JSON_DATA, ERR_DATA_A, ERR_DATA_B = 0x175ef30, 0x175cc70, 0x1740910, 0x17409d0
UNWIND = 0x63f0a50
G_MALLOC, G_FREE, G_ALLOC_ERR, G_ASSERT, G_SUB_OVF = 0x64df480, 0x64df4a0, 0x64df498, 0x64df730, 0x64df848
G_NEXT_BACK, G_ENSURE, G_WRITE = 0x64e0938, 0x64e0028, 0x64e09e8
MEMCPY_SLOT = 0x64df508
PANIC_SLOTS = {G_ALLOC_ERR: "alloc-error", G_ASSERT: "assert", G_SUB_OVF: "depth-underflow", 0x64df520: "add-overflow"}
STUB_SLOTS = (G_MALLOC, G_FREE, G_NEXT_BACK, G_ENSURE, G_WRITE, G_REALLOC, MEMCPY_SLOT)
UNUSED_SLOTS = {G_ALIGNED_REALLOC: "aligned-realloc", G_ALIGNED_ALLOC: "aligned-alloc"}
STUB_CALLS = (ESCAPE, RMP_STRUCT, VALUE_A, VALUE_B, ERR_SLOT_N, ERR_SLOT_S, RMP_DATA, JSON_DATA,
              ERR_DATA_A, ERR_DATA_B)
ERR_RET = {ERR_SLOT_N: 0x0e44_0000_0000_0001, ERR_SLOT_S: 0x0e44_0000_0000_0002,
           ERR_DATA_A: 0x0e44_0000_0000_0003, ERR_DATA_B: 0x0e44_0000_0000_0004}

# Rodata strings read from the bytes at tool time.
EXT_RMP_AT, INDENT_STRUCT, INDENT_DATA = 0x4659e5, 0x91b3c4, 0x4801fc
KEYS_STRUCT = ((0x91c305, 3), (0x91c308, 1), (0x91c309, 1))
CFG_WORD = 0x1000400            # msgpack serializer configuration dword written before the struct driver call
NIL_ERR_RECORD = (ERR_TAG, 0, 0x2600000003)

PATH_AT = 0x7100_0000_0000
DATA_AT = 0x7180_0000_0000
HEAP_AT = 0x7800_0000_0000
DATA_SIZE = 0x100
STACK_TOP = rm.STACK_TOP
SAVED_REGS = (3, 5, 12, 13, 14, 15)
SAVED = tuple(0x5150_0000_0000_0000 | (k << 8) for k in SAVED_REGS)
JUNK = rm.JUNK


# ---------------------------------------------------------------- shared environment
class ModelPanic(Exception):
    def __init__(self, kind, a, b):
        super().__init__(kind)
        self.kind, self.a, self.b = kind, a, b


class PyVec:
    def __init__(self, cap, ptr, ln):
        self.cap, self.ptr, self.len = cap, ptr, ln


class MemVec:
    """A Rust Vec<u8> header (cap, ptr, len) held in evaluator memory."""

    def __init__(self, m, at):
        self.m, self.at = m, at

    cap = property(lambda s: s.m.load(s.at, 8), lambda s, v: s.m.store(s.at, 8, v))
    ptr = property(lambda s: s.m.load(s.at + 8, 8), lambda s, v: s.m.store(s.at + 8, 8, v))
    len = property(lambda s: s.m.load(s.at + 16, 8), lambda s, v: s.m.store(s.at + 16, 8, v))


class PySer:
    """serde_json pretty serializer state: writer vec, indent string, current depth, has_value."""

    def __init__(self, vec, ind_ptr, ind_len, depth, hv):
        self.vec, self.ind_ptr, self.ind_len, self.depth, self.hv = vec, ind_ptr, ind_len, depth, hv

    def view(self):
        return (self.ind_ptr, self.ind_len, self.depth, self.hv)


class MemSer:
    def __init__(self, m, at):
        self.m, self.at = m, at
        self.vec = MemVec(m, m.load(at, 8))

    def view(self):
        return tuple(self.m.load(self.at + o, 8) for o in (8, 16, 24)) + (self.m.load(self.at + 32, 1),)

    @property
    def ind_len(self):
        return self.m.load(self.at + 16, 8)

    @ind_len.setter
    def ind_len(self, v):
        self.m.store(self.at + 16, 8, v)

    @property
    def ind_ptr(self):
        return self.m.load(self.at + 8, 8)

    @property
    def depth(self):
        return self.m.load(self.at + 24, 8)

    @depth.setter
    def depth(self, v):
        self.m.store(self.at + 24, 8, v)


class ModelMem:
    def __init__(self, image, path):
        self.image, self.allocs = image, {PATH_AT: bytearray(path)}

    def alloc(self, base, n):
        self.allocs[base] = bytearray(n)

    def rd(self, at, n):
        if n == 0:
            return b""
        for base, buf in self.allocs.items():
            if base <= at and at + n <= base + len(buf):
                return bytes(buf[at - base:at - base + n])
        return self.image.read(at, n)

    def wr(self, at, data):
        for base, buf in self.allocs.items():
            if base <= at and at + len(data) <= base + len(buf):
                buf[at - base:at - base + len(data)] = data
                return
        fail(f"model write outside allocations at {at:#x}")


class MachineMem:
    def __init__(self, m):
        self.m = m

    def alloc(self, base, n):
        self.m.add_region(base, n)

    def rd(self, at, n):
        if n == 0:
            return b""
        try:
            return bytes(self.m.load(at + i, 1) for i in range(n))
        except ToolError:
            return self.m.image.read(at, n)

    def wr(self, at, data):
        for i, b in enumerate(data):
            self.m.store(at + i, 1, b)


def lower(b):
    return bytes(c + 32 if 65 <= c <= 90 else c for c in b)


class Env:
    """Every callee of the three bodies, with one behaviour shared by the model and the evaluator stubs."""

    def __init__(self, case, mem):
        self.case, self.mem, self.log = case, mem, []
        self.next_heap = HEAP_AT
        self.events = 0
        self.sizes = {}
        self.stream = rm.Stream("env/" + str(case["k"]))

    def ev(self, *row):
        self.log.append(tuple(row))

    def alloc(self, n):
        base = self.next_heap
        self.next_heap += ((max(n, 1) + 15) & ~15) + 16
        self.mem.alloc(base, max(n, 1))
        return base

    def fails_now(self):
        self.events += 1
        return self.case["fail_at"] == self.events

    def malloc(self, n):
        self.ev("malloc", n)
        if self.fails_now():
            return 0
        base = self.alloc(n)
        self.sizes[base] = n
        return base

    def realloc(self, ptr, n):
        self.ev("realloc", ptr, n)
        if self.fails_now():
            return 0
        base = self.alloc(n)
        keep = min(self.sizes[ptr], n)
        self.mem.wr(base, self.mem.rd(ptr, keep))
        self.sizes[base] = n
        return base

    def free(self, ptr, size, flag):
        self.ev("free", ptr, size, flag)

    def reserve(self, vec, add):
        """RawVec<u8>::grow_amortized (0x5963a10): new capacity max(2 * cap, len + add, 8)."""
        cap = max(vec.cap * 2, vec.len + add, 8)
        new = self.malloc(cap) if vec.cap == 0 else self.realloc(vec.ptr, cap)
        if new == 0:
            raise ModelPanic("alloc-error", 1, cap)
        vec.cap, vec.ptr = cap, new

    def push(self, vec, data):
        if vec.cap - vec.len < len(data):
            self.reserve(vec, len(data))
        self.mem.wr(vec.ptr + vec.len, data)
        vec.len += len(data)

    def next_back(self, ptr, ln, tag, flags, absb):
        self.ev("next_back", ptr, ln, tag, flags, absb)
        c = self.case
        path = self.mem.rd(ptr, ln)
        parts = path.rstrip(b"/").split(b"/") if path.rstrip(b"/") else [b""]
        name = parts[-1]
        off = len(path.rstrip(b"/")) - len(name)
        if c["comp"] == "whole":
            return 9, ptr, ln
        if c["comp"] == "dotdot":
            return 9, ptr + max(ln - 2, 0), 2
        if c["comp"] == "other" or name in (b"", b".", b".."):
            return c["other_tag"], 0, 0
        return 9, ptr + off, len(name)

    def ensure(self, ptr, ln):
        self.ev("ensure", ptr, ln)
        return self.case["ensure_rc"]

    def write(self, buf, ln, ptr, plen, extra):
        self.ev("write", buf, ln, self.mem.rd(buf, ln), ptr, plen, extra)
        return self.case["write_rc"]

    def err(self, which, path_ptr, path_len, words):
        self.ev("err", which, path_ptr, path_len, tuple(words))
        return ERR_RET[which]

    def escape(self, vec, ptr, ln):
        self.ev("escape", ln)
        self.push(vec, self.mem.rd(ptr, ln))

    def blob(self, n):
        return b"".join(bytes([0x41 + (b % 26)]) for b in self.stream.take(n)) if n else b""

    def rmp_ok(self, vec):
        n = self.case["ser_bytes"]
        if n:
            self.push(vec, self.blob(n))
        self.ev("ser_rmp_ok", n)

    def value_a(self, arg, ser):
        self.ev("value_a", arg, ser.view())
        self.push(ser.vec, b"<a>" + self.blob(self.case["val_bytes"][0]))
        ser.ind_len = self.case["ind_len"]
        return None

    def value_b(self, which, arg, ser):
        self.ev("value_b", which, arg, ser.view())
        fail_at = self.case["val_fail"]
        if fail_at == which:
            self.ev("value_b_fail", which)
            return 0x0bad_0000_0000_0100 + which
        self.push(ser.vec, b"<b%d>" % which + self.blob(self.case["val_bytes"][which]))
        if which == 2:
            ser.depth = self.case["depth_after"]
        return 0


# ---------------------------------------------------------------- reconstruction
def model_front(env, path_ptr, plen, mut):
    """Returns "null", "rmp" or "json" for the path."""
    mem = env.mem
    if "no-devnull" not in mut and plen == 9 and mem.rd(path_ptr, 9) == b"/dev/null":
        return "null"
    absb = 1 if plen and mem.rd(path_ptr, 1) == b"/" else 0
    if "abs-always" in mut:
        absb = 1
    tag, nptr, nlen = env.next_back(path_ptr, plen, 6, 0x201, absb)
    if tag != 9:
        return "json"
    if "no-dotdot" not in mut and nlen == 2 and mem.rd(nptr, 2) == b"..":
        return "json"
    i = nlen
    while True:
        if i == 0:
            return "json"
        i -= 1
        if mem.rd(nptr + i, 1) == b".":
            break
    if i == 0 and "hidden-ext" not in mut:
        return "json"
    ext = mem.rd(nptr + i + 1, nlen - i - 1)
    if "case-sensitive" in mut:
        return "rmp" if ext == b"rmp" else "json"
    if "prefix-ext" in mut:
        return "rmp" if lower(ext)[:3] == b"rmp" else "json"
    return "rmp" if len(ext) == 3 and lower(ext) == b"rmp" else "json"


def finish(env, ptr, ln, cap, path_ptr, plen, extra, always_free, mut):
    rax = env.ensure(path_ptr, plen)
    if rax == 0 or "ensure-ignored" in mut:
        rax = env.write(ptr, ln, path_ptr, plen, extra)
    if "no-free" in mut:
        return rax
    if cap or always_free:
        env.free(ptr, cap, 0)
    return rax


def model_nil(env, path_ptr, plen, extra, mut=frozenset()):
    kind = model_front(env, path_ptr, plen, mut)
    if kind == "null":
        return 0
    if kind == "rmp":
        ptr = env.malloc(8)     # 0x5963650(out, 0, 1, 8, 1, 1): eight bytes, alignment 1
        if ptr == 0:
            return env.err(ERR_SLOT_N, path_ptr, plen, NIL_ERR_RECORD)
        env.mem.wr(ptr, b"\xc1" if "nil-byte" in mut else b"\xc0")
        ptr_, ln, cap = ptr, 1, 8
    else:
        ptr = env.malloc(0x80)
        if ptr == 0:
            raise ModelPanic("alloc-error", 1, 0x80)
        env.mem.wr(ptr, b"nulL" if "null-text" in mut else b"null")
        ptr_, ln, cap = ptr, 4, 0x80
    return finish(env, ptr_, ln, cap, path_ptr, plen, extra, True, mut)


def model_struct(env, data, path_ptr, plen, extra, mut=frozenset()):
    kind = model_front(env, path_ptr, plen, mut)
    if kind == "null":
        return 0
    if kind == "rmp":
        vec = PyVec(0, 1, 0)
        env.ev("ser_struct_cfg", data, CFG_WORD ^ (1 if "cfg" in mut else 0), 0)
        if env.case["ser_fail"] is None:
            env.rmp_ok(vec)
        else:
            env.ev("ser_rmp_err", env.case["ser_bytes"] // 2)
            if env.case["ser_bytes"] // 2:
                env.push(vec, env.blob(env.case["ser_bytes"] // 2))
            if vec.cap:
                env.free(vec.ptr, vec.cap, 0)
            return env.err(ERR_SLOT_N, path_ptr, plen, env.case["ser_fail"])
        return finish(env, vec.ptr, vec.len, vec.cap, path_ptr, plen, extra, False, mut)
    ptr = env.malloc(0x80)
    if ptr == 0:
        raise ModelPanic("alloc-error", 1, 0x80)
    env.mem.wr(ptr, b"[" if "open-bracket" in mut else b"{")
    vec = PyVec(0x80, ptr, 1)
    ser = PySer(vec, INDENT_STRUCT, 2, 1, 0)
    first = True

    def key(k):
        nonlocal first
        kptr, klen = k
        if first:
            env.push(vec, b"\n")
        else:
            env.push(vec, b",\n")
        first = False
        for _ in range(ser.depth):
            env.push(vec, env.mem.rd(ser.ind_ptr, ser.ind_len))
        env.push(vec, b'"')
        env.escape(vec, kptr, klen)
        env.push(vec, b'"')
        env.push(vec, b" :" if "colon-swap" in mut else b": ")

    def fail_out(rax):
        if vec.cap:
            env.free(vec.ptr, vec.cap, 0)
        return env.err(ERR_SLOT_S, path_ptr, plen, (rax,))

    key(KEYS_STRUCT[0])
    env.value_a(data + 0x30, ser)
    ser.hv = 1
    key(KEYS_STRUCT[1])
    rax = env.value_b(1, data, ser)
    if rax:
        return fail_out(rax)
    ser.hv = 1
    key(KEYS_STRUCT[2])
    rax = env.value_b(2, data + 0x18, ser)
    if rax:
        return fail_out(rax)
    ser.hv = 1
    if ser.depth == 0 and "no-underflow-check" not in mut:
        raise ModelPanic("depth-underflow", 0x64a1e40, 0)
    ser.depth -= 1
    env.push(vec, b"\n")
    for _ in range(ser.depth):
        env.push(vec, env.mem.rd(ser.ind_ptr, ser.ind_len))
    env.push(vec, b"}")
    return finish(env, vec.ptr, vec.len, vec.cap, path_ptr, plen, extra, False, mut)


def model_data(env, data, path_ptr, plen, extra, mut=frozenset()):
    kind = model_front(env, path_ptr, plen, mut)
    if kind == "null":
        return 0
    if kind == "rmp":
        vec = PyVec(0, 1, 0)
        if env.case["ser_fail"] is None:
            env.rmp_ok(vec)
        else:
            env.ev("ser_rmp_err", env.case["ser_bytes"] // 2)
            if env.case["ser_bytes"] // 2:
                env.push(vec, env.blob(env.case["ser_bytes"] // 2))
            if vec.cap:
                env.free(vec.ptr, vec.cap, 0)
            return env.err(ERR_DATA_A, path_ptr, plen, env.case["ser_fail"])
        return finish(env, vec.ptr, vec.len, vec.cap, path_ptr, plen, extra, False, mut)
    ptr = env.malloc(0x80)
    if ptr == 0:
        raise ModelPanic("alloc-error", 1, 0x80)
    vec = PyVec(0x80, ptr, 0 if "len-one" not in mut else 1)
    ser = PySer(vec, INDENT_DATA, 2, 0, 0)
    env.ev("ser_json", ser.view())
    n = env.case["ser_bytes"]
    if n:
        env.push(vec, env.blob(n))
    if env.case["json_fail"]:
        env.ev("ser_json_fail")
        if vec.cap:
            env.free(vec.ptr, vec.cap, 0)
        return env.err(ERR_DATA_B, path_ptr, plen, (env.case["json_fail"],))
    return finish(env, vec.ptr, vec.len, vec.cap, path_ptr, plen, extra, False, mut)


MODELS = {"nil": model_nil, "struct": model_struct, "data": model_data}


# ---------------------------------------------------------------- evaluator
class BodyMachine(rm.TraceMachine):
    def clobber(self):
        for r in (1, 6, 8, 9, 10, 11):
            self.regs[r] = JUNK + r
        for i in range(16):
            self.xmm[i] = (JUNK << 64) | i


def install(m, env, image, body):
    """Connect every callee of the three bodies to the environment."""
    mem = env.mem
    st = m.stubs
    st.clear()
    reg = m.regs

    def word(slot):
        return image.word(slot)

    def ret(v):
        m.clobber()
        reg[0] = v & M64

    def malloc(_):
        ret(env.malloc(reg[7]))

    def free(_):
        env.free(reg[7], reg[6], reg[2])
        m.clobber()
        reg[0] = JUNK

    def next_back(_):
        out, state = reg[7], reg[6]
        ptr, ln = m.load(state, 8), m.load(state + 8, 8)
        tag, flags, absb = m.load(state + 16, 1), m.load(state + 0x38, 2), m.load(state + 0x3a, 1)
        t, p, n = env.next_back(ptr, ln, tag, flags, absb)
        m.store(out, 8, t)
        m.store(out + 8, 8, p)
        m.store(out + 16, 8, n)
        ret(JUNK)

    def ensure(_):
        ret(env.ensure(reg[7], reg[6]))

    def write(_):
        ret(env.write(reg[7], reg[6], reg[2], reg[1], reg[8]))

    def realloc(_):
        ret(env.realloc(reg[7], reg[6]))

    def escape(_):
        env.escape(MemVec(m, reg[7]), reg[6], reg[2])
        ret(JUNK)

    def rmp_struct(_):
        out, data, cfg = reg[7], reg[6], reg[2]
        env.ev("ser_struct_cfg", data, m.load(cfg + 8, 4), m.load(cfg + 12, 1))
        vec = MemVec(m, m.load(cfg, 8))
        res = env.case["ser_fail"]
        if res is None:
            env.rmp_ok(vec)
            words = (OK_TRIPLE, 0, 0)
        else:
            env.ev("ser_rmp_err", env.case["ser_bytes"] // 2)
            if env.case["ser_bytes"] // 2:
                env.push(vec, env.blob(env.case["ser_bytes"] // 2))
            words = res
        for i, w in enumerate(words):
            m.store(out + 8 * i, 8, w)
        ret(JUNK)

    def rmp_data(_):
        out, vec, data = reg[7], MemVec(m, reg[6]), reg[2]
        res = env.case["ser_fail"]
        if res is None:
            env.rmp_ok(vec)
            words = (OK_TRIPLE, 0, 0)
        else:
            env.ev("ser_rmp_err", env.case["ser_bytes"] // 2)
            if env.case["ser_bytes"] // 2:
                env.push(vec, env.blob(env.case["ser_bytes"] // 2))
            words = res
        for i, w in enumerate(words):
            m.store(out + 8 * i, 8, w)
        ret(JUNK)

    def value_a(_):
        env.value_a(reg[7], MemSer(m, reg[6]))
        ret(JUNK)

    def value_b(_):
        # 0x50472b0 is called as (ser, data) for field 1 and (ser, data + 0x18) for field 2
        ser, arg = reg[7], reg[6]
        which = 1 if arg == reg_data(m) else 2
        ret(env.value_b(which, arg, MemSer(m, ser)))

    def reg_data(machine):
        return machine.data_at

    def json_data(_):
        data, serp = reg[7], reg[6]
        ser = MemSer(m, serp)
        env.ev("ser_json", ser.view())
        n = env.case["ser_bytes"]
        if n:
            env.push(ser.vec, env.blob(n))
        if env.case["json_fail"]:
            env.ev("ser_json_fail")
            ret(env.case["json_fail"])
        else:
            ret(0)

    def error_n(which):
        def f(_):
            ptr, ln = m.load(reg[7], 8), m.load(reg[7] + 8, 8)
            rec = tuple(m.load(reg[6] + 8 * i, 8) for i in range(3))
            ret(env.err(which, ptr, ln, rec))
        return f

    def error_one(which):
        def f(_):
            ptr, ln = m.load(reg[7], 8), m.load(reg[7] + 8, 8)
            ret(env.err(which, ptr, ln, (reg[6],)))
        return f

    def memcpy(_):
        dst, src, n = reg[7], reg[6], reg[2]
        mem.wr(dst, mem.rd(src, n))
        reg[0] = dst

    st[word(MEMCPY_SLOT)] = memcpy
    st[word(G_MALLOC)] = malloc
    st[word(G_FREE)] = free
    st[word(G_NEXT_BACK)] = next_back
    st[word(G_ENSURE)] = ensure
    st[word(G_WRITE)] = write
    for slot, kind in PANIC_SLOTS.items():
        st[word(slot)] = kind
    st[word(G_REALLOC)] = realloc
    for slot, kind in UNUSED_SLOTS.items():
        st[word(slot)] = kind
    st[ESCAPE] = escape
    st[RMP_STRUCT] = rmp_struct
    st[RMP_DATA] = rmp_data
    st[VALUE_A] = value_a
    st[VALUE_B] = value_b
    st[JSON_DATA] = json_data
    st[ERR_SLOT_N] = error_n(ERR_SLOT_N)
    st[ERR_SLOT_S] = error_one(ERR_SLOT_S)
    st[ERR_DATA_A] = error_n(ERR_DATA_A)
    st[ERR_DATA_B] = error_one(ERR_DATA_B)
    st[UNWIND] = "unwind"

    def guard(fn):
        def wrapped(machine):
            try:
                fn(machine)
            except ModelPanic as p:  # a callee's own growth failed: it panics in the callee, as the model does
                reg[7], reg[6] = p.a, p.b
                raise Boundary(p.kind, reg)
        return wrapped

    for key, fn in list(st.items()):
        if callable(fn):
            st[key] = guard(fn)


def run_machine(m, image, body, case):
    m.reset()
    mem = MachineMem(m)
    env = Env(case, mem)
    path = case["path"]
    m.add_region(PATH_AT, max(len(path), 1), path)
    m.add_region(DATA_AT, DATA_SIZE, b"\x5a" * DATA_SIZE)
    m.data_at = DATA_AT
    install(m, env, image, body)
    for k, v in zip(SAVED_REGS, SAVED):
        m.regs[k] = v
    m.regs[7], m.regs[6], m.regs[2], m.regs[1] = DATA_AT, PATH_AT, len(path), case["extra"]
    if body == "nil":
        m.regs[7] = JUNK
    m.regs[8], m.regs[9] = JUNK + 8, JUNK + 9
    try:
        m.run(BODIES[body], limit=400000)
        panic = None
    except Boundary as b:
        panic = (b.kind, b.regs[7], b.regs[6] if b.kind == "alloc-error" else 0)
    return {"rax": m.regs[0] if panic is None else None, "panic": panic, "log": env.log,
            "regs_ok": panic is not None or ([m.regs[k] for k in SAVED_REGS] == list(SAVED)
                                             and m.regs[4] == STACK_TOP - 0x100)}


def run_model(image, body, case, mut=frozenset()):
    mem = ModelMem(image, case["path"])
    env = Env(case, mem)
    try:
        if body == "nil":
            rax = model_nil(env, PATH_AT, len(case["path"]), case["extra"], mut)
        else:
            rax = MODELS[body](env, DATA_AT, PATH_AT, len(case["path"]), case["extra"], mut)
        panic = None
    except ModelPanic as p:
        rax, panic = None, (p.kind, p.a, p.b)
    return {"rax": rax, "panic": panic, "log": env.log}


def compare(want, got):
    if got.get("regs_ok") is False:
        return "callee-saved registers or stack pointer changed"
    if want["panic"] != got["panic"]:
        return f"panic {want['panic']} != {got['panic']}"
    if want["rax"] != got["rax"]:
        return f"result {want['rax']} != {got['rax']}"
    if want["log"] != got["log"]:
        for i, (a, b) in enumerate(zip(want["log"], got["log"])):
            if a != b:
                return f"event {i}: {a} != {b}"
        return f"event count {len(want['log'])} != {len(got['log'])}"
    return None


# ---------------------------------------------------------------- cases
NAMES = (b"a.rmp", b"b.RMP", b"c.Rmp", b"d.rMP", b"state.json", b"x.rmpx", b"x.rm", b"y.", b".rmp", b".hidden",
         b"noext", b"a.b.rmp", b"a.rmp.json", b"..", b".", b"abc.RMp", b"q.rmq", b"w.\xffmp", b"...", b"a..rmp",
         b"z.rmp ", b"e.bin", b"f.RMP", b"g.tar.rmp", b"h.r", b"k.rmpp", b"..rmp", b"..x.rmp", b"...rmp", b"ab", b".r", b"r.",
         b"a.rm", b"A.RmP")
DIRS = (b"", b"/", b"a/", b"/a/b/", b"../", b"./", b"/q/x/", b"s/t/u/", b"//", b"/a/")
SPECIAL = (b"/dev/null", b"/dev/nulx", b"/dev/nul", b"/dev/null2", b"/dev/NULL", b"dev/null", b"", b"/", b"//dev/null",
           b"/dev/null/", b"abcdefghi", b"/dev/null\x00")
FAULTS = ((OK_TRIPLE + 1, 7, 9), (0x0bad_0000_0000_0011, 0, 0), (ERR_TAG | 5, 1, 2), (1, 2, 3), (0, 0, 0))


def make_case(body, k):
    s = rm.Stream(f"{body}/{k}")
    b = s.below
    if b(100) < 7:
        path = s.pick(SPECIAL)
    else:
        name = s.pick(NAMES)
        path = s.pick(DIRS) + name
        if b(12) == 0:
            path += b"/" * (1 + b(2))
    comp = "auto"
    r = b(100)
    if r < 6:
        comp = "other"
    elif r < 12 and len(path) >= 2:
        comp = "dotdot"
    junk = lambda: 0x0bad_0000_0000_0000 | b(1 << 30) << 4
    case = {"k": k, "body": body, "path": path, "comp": comp, "other_tag": s.pick((0, 1, 2, 3, 4, 5, 6, 7, 8)),
            "extra": junk() | 1, "ensure_rc": 0 if b(100) < 78 else junk() | 2, "write_rc": 0 if b(100) < 75 else junk() | 3,
            "fail_at": 0 if b(100) < 90 else 1 + b(3), "ser_bytes": s.pick((0, 1, 5, 17, 40, 79, 80, 81, 127, 128, 200, 333, b(400))),
            "ser_fail": None if b(100) < 82 else s.pick(FAULTS), "json_fail": 0 if b(100) < 90 else junk() | 4,
            "val_bytes": (b(60), b(70), b(90)) if b(2) else (b(5), b(5), b(5)),
            "val_fail": 0 if b(100) < 88 else 1 + b(2), "depth_after": s.pick((1, 1, 1, 1, 1, 2, 3, 0)),
            "ind_len": s.pick((2, 2, 2, 2, 2, 2, 0, 1, 3))}
    case["val_bytes"] = {0: case["val_bytes"][0], 1: case["val_bytes"][1], 2: case["val_bytes"][2]}
    return case


COUNTS = {"nil": 3600, "struct": 4400, "data": 4000}


def all_cases():
    for body in ("nil", "struct", "data"):
        for k in range(COUNTS[body]):
            yield make_case(body, k)


def case_row(c, want):
    kind = "-"
    log = want["log"]
    first = log[0][0] if log else "-"
    return "\t".join((c["body"], str(c["k"]), c["path"].hex() or "-", c["comp"], "1" if c["fail_at"] else "0",
                      "-" if c["ser_fail"] is None else "E", str(c["ser_bytes"]),
                      "panic:" + want["panic"][0] if want["panic"] else f"{want['rax']:#x}",
                      str(len(log)), first, hashlib.sha256(repr(log).encode()).hexdigest()[:12]))


# ---------------------------------------------------------------- static evidence
def fde_end(image, va):
    _, fdes = rm.fde_extents.eh_frame_records(image.data, image.secs)
    for f in fdes:
        if f["start"] == va:
            return f["end"]
    fail(f"no FDE at {va:#x}")


def sweep_body(image, va):
    end = None
    _, fdes = rm.fde_extents.eh_frame_records(image.data, image.secs)
    for f in fdes:
        if f["start"] == va:
            end = f["end"]
    if end is None:
        fail(f"no FDE at {va:#x}")
    return end, rm.sweep(image, va, end)


def static_rows(image):
    rows = []
    for name, va in list(BODIES.items()) + list(REALS.items()):
        try:
            end, insns = sweep_body(image, va)
        except ToolError:
            # 0x159fca0 holds a SSE loop for 16+ byte strings that the evaluator decoder does not know; the
            # three-byte comparison path never reaches it, so only the extent and hash are recorded.
            if name != "extcmp":
                raise
            end, insns = fde_end(image, va), []
        calls = []
        for v, f in insns:
            if f["op"] in (0xe8, 0xe9):
                calls.append(("c" if f["op"] == 0xe8 else "j", f["target"], v))
            elif f["op"] == 0xff and f["reg"] & 7 in (2, 4) and f["rm"][0] == "m" and f["rm"][1] == "rip":
                calls.append(("got", v + f["len"] + f["rm"][4], v))
        rows.append({"name": name, "start": va, "end": end, "insns": len(insns),
                     "sha256": hashlib.sha256(image.code(va, end - va)).hexdigest(),
                     "calls": calls, "va_list": [v for v, _ in insns]})
    return rows


def check_static(image, rows):
    known = {*STUB_CALLS, *REALS.values(), UNWIND}
    slots = {*STUB_SLOTS, *PANIC_SLOTS, *UNUSED_SLOTS}
    for r in rows:
        for kind, target, at in r["calls"]:
            if kind == "got":
                if target not in slots:
                    fail(f"{r['name']}: unexpected import slot {target:#x} at {at:#x}")
            elif kind == "c" and target not in known and not (r["start"] <= target < r["end"]):
                fail(f"{r['name']}: unexpected call target {target:#x} at {at:#x}")
    if image.read(EXT_RMP_AT, 3) != b"rmp":
        fail("extension string is not rmp")
    for ptr, n in KEYS_STRUCT:
        if not image.read(ptr, n).isascii():
            fail("struct key is not ascii")
    if image.read(INDENT_STRUCT, 2) != b"  " or image.read(INDENT_DATA, 2) != b"  ":
        fail("indent strings are not two spaces")


# ---------------------------------------------------------------- controls
MODEL_MUTANTS = ("no-devnull", "abs-always", "no-dotdot", "hidden-ext", "case-sensitive", "prefix-ext", "ensure-ignored",
                 "no-free", "nil-byte", "null-text", "cfg", "open-bracket", "colon-swap", "no-underflow-check", "len-one")
# The ".." test (cmpw $0x2e2e on a two-byte name) can be removed or inverted without changing any result: a two-byte
# name cannot have a non-empty extension after a dot at index >= 1, so it always selects JSON.  These four mutations
# are therefore equivalent mutants, listed in equivalents.tsv and not counted as negative controls.
EQUIVALENT = {"no-dotdot", "nil:0x50de3a7", "struct:0x50de5dd", "data:0x17406fc"}
FLIP = {0x74: 0x75, 0x75: 0x74, 0x72: 0x73, 0x73: 0x72, 0x76: 0x77, 0x77: 0x76, 0x78: 0x79, 0x79: 0x78,
        0x7c: 0x7d, 0x7d: 0x7c, 0x7e: 0x7f, 0x7f: 0x7e}


def evaluate(image, cases, override=None, stop_on_first=False, trace=None, mut=frozenset()):
    m = BodyMachine(image, override)
    if trace is not None:
        m.seen = trace
    results, misses = [], []
    for c in cases:
        want = run_model(image, c["body"], c, mut)
        try:
            got = run_machine(m, image, c["body"], c)
        except ToolError as e:
            if override is None:
                raise
            got = {"error": str(e)}
        why = "machine-error" if "error" in got else compare(want, got)
        results.append((want, got))
        if why:
            misses.append((c["body"], c["k"], why))
            if stop_on_first:
                break
    return results, misses


def model_controls(image, cases):
    rows = []
    for mut in MODEL_MUTANTS:
        hit = None
        for c in cases:
            m_want = run_model(image, c["body"], c, frozenset([mut]))
            c_want = c["_want"]
            why = compare(m_want, {**c_want, "regs_ok": True})
            if why:
                hit = (c["body"], c["k"], why)
                break
        rows.append(("model", mut, hit))
    return rows


def byte_sites(image, rows):
    sites = []
    for r in rows:
        if r["name"] not in BODIES:
            continue
        for v, f in sweep_body(image, r["start"])[1]:
            b = f["bytes"]
            if b[0] in FLIP:
                sites.append((r["name"], v, v, FLIP[b[0]]))
            elif b[0] == 0x0f and 0x80 <= b[1] <= 0x8f:
                sites.append((r["name"], v, v + 1, b[1] ^ 1))
    return sites


def immediate_sites(image, rows):
    """Byte constants stored by the bodies: 0xc0 nil, 0x7b '{', 0x7d '}', 0x0a newline."""
    wanted = {0xc0: "nil-byte", 0x7b: "open-brace", 0x7d: "close-brace", 0x0a: "newline", 0x22: "quote"}
    out = []
    for r in rows:
        if r["name"] not in BODIES:
            continue
        for v, f in sweep_body(image, r["start"])[1]:
            b = f["bytes"]
            if f["op"] == 0xc6 and b[-1] in wanted:
                out.append((r["name"], v, v + f["len"] - 1, b[-1] ^ 0x01, wanted[b[-1]]))
    return out


def byte_controls(image, cases, sites, seen, subset_n=120):
    rows = []
    per = {name: [c for c in cases if c["body"] == name][:subset_n] for name in BODIES}
    for name, insn, at, new, *label in sites:
        tag = f"{name}:{insn:#x}" + (f":{label[0]}" if label else "")
        if insn not in seen:
            rows.append(("byte", tag, "unreached"))
            continue
        _, misses = evaluate(image, per[name], {at: new}, stop_on_first=True)
        rows.append(("byte", tag, misses[0] if misses else None))
    return rows


def input_controls(image, cases):
    """Damaged hash, truncated image and out-of-range inputs must be refused or detected."""
    rows = []
    try:
        rm.Image(image.data[:-1])
        rows.append(("input", "binary-truncated", None))
    except ToolError as e:
        rows.append(("input", "binary-truncated", ("-", 0, str(e))))
    bad = bytearray(image.data)
    bad[0x1000] ^= 1
    try:
        rm.Image(bytes(bad))
        rows.append(("input", "binary-bit-flip", None))
    except ToolError as e:
        rows.append(("input", "binary-bit-flip", ("-", 0, str(e))))
    # a body address that is not the start of its FDE must fail the static check
    try:
        sweep_body(image, NIL + 4)
        rows.append(("input", "body-address-shifted", None))
    except ToolError as e:
        rows.append(("input", "body-address-shifted", ("-", 0, str(e))))
    # a mutated call target table is refused
    try:
        check_static(image, [{"name": "x", "start": 0, "end": 1, "calls": [("got", 0x64dffff, 0)]}])
        rows.append(("input", "unknown-import-slot", None))
    except ToolError as e:
        rows.append(("input", "unknown-import-slot", ("-", 0, str(e))))
    try:
        check_static(image, [{"name": "x", "start": 0, "end": 1, "calls": [("c", 0x1234567, 0)]}])
        rows.append(("input", "unknown-call-target", None))
    except ToolError as e:
        rows.append(("input", "unknown-call-target", ("-", 0, str(e))))
    return rows


def coverage(rows, seen):
    out = []
    for r in rows:
        hit = [v for v in r["va_list"] if v in seen]
        out.append((r["name"], r["start"], len(r["va_list"]), len(hit)))
    return out


# ---------------------------------------------------------------- driver
SAMPLE_EVERY = 2


def generate(out):
    data = BINARY.read_bytes()
    image = rm.Image(data)
    rows = static_rows(image)
    check_static(image, rows)
    cases = list(all_cases())
    seen = set()
    results, misses = evaluate(image, cases, trace=seen)
    if misses:
        fail(f"{len(misses)} cases differ from the reconstruction, first {misses[0]}")
    for c, (want, _) in zip(cases, results):
        c["_want"] = want
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "bodies.tsv", "w", newline="\n") as f:
        f.write("name\tstart\tend\tinstructions\tsha256\tcall_sites\n")
        for r in rows:
            sites = " ".join(f"{k}:{t:#x}@{a:#x}" for k, t, a in r["calls"])
            f.write(f"{r['name']}\t{r['start']:#x}\t{r['end']:#x}\t{r['insns']}\t{r['sha256']}\t{sites}\n")
    cov = coverage(rows, seen)
    with open(out / "coverage.tsv", "w", newline="\n") as f:
        f.write("name\tstart\tinstructions\treached\n")
        for name, start, total, hit in cov:
            f.write(f"{name}\t{start:#x}\t{total}\t{hit}\n")
    lines = ["body\tk\tpath_hex\tcomponent\tfail_at\tser_fault\tser_bytes\tresult\tevents\tfirst_event\tlog_digest"]
    digest = hashlib.sha256()
    outcome = {}
    for c, (want, _) in zip(cases, results):
        row = case_row(c, want)
        digest.update(row.encode() + b"\n")
        key = c["body"] + ":" + ("panic:" + want["panic"][0] if want["panic"] else "rax-zero" if want["rax"] == 0 else "rax-nonzero")
        outcome[key] = outcome.get(key, 0) + 1
        if c["k"] % SAMPLE_EVERY == 0:
            lines.append(row)
    (out / "cases-sample.tsv").write_text("\n".join(lines) + "\n")
    crow = model_controls(image, cases)
    sites = byte_sites(image, rows) + immediate_sites(image, rows)
    crow += byte_controls(image, cases, sites, seen)
    crow += input_controls(image, cases)
    equiv = [r for r in crow if r[2] is None and r[1] in EQUIVALENT]
    if len(equiv) != len(EQUIVALENT):
        fail("the equivalent mutants are not all undetected")
    crow = [r for r in crow if r not in equiv]
    with open(out / "equivalents.tsv", "w", newline="\n") as f:
        f.write("kind\tmutation\treason\n")
        for kind, mut, _ in equiv:
            f.write(f"{kind}\t{mut}\ttwo-byte names never select rmp, so the dot-dot test cannot change a result\n")
    with open(out / "controls.tsv", "w", newline="\n") as f:
        f.write("kind\tmutation\tbody\tfirst_detecting_case\treason\n")
        for kind, mut, hit in crow:
            if hit is None:
                f.write(f"{kind}\t{mut}\t-\t-\tundetected\n")
            elif hit == "unreached":
                f.write(f"{kind}\t{mut}\t-\t-\tunreached\n")
            else:
                f.write(f"{kind}\t{mut}\t{hit[0]}\t{hit[1]}\t{hit[2][:60].replace(chr(9), ' ')}\n")
    live = [r for r in crow if r[2] != "unreached"]
    detected = sum(1 for r in live if r[2] is not None)
    summary = {"binary_sha256": SHA256, "cases": len(cases), "mismatches": 0, "all_case_rows_sha256": digest.hexdigest(),
               "sample_every": SAMPLE_EVERY, "outcomes": dict(sorted(outcome.items())),
               "counts": COUNTS, "controls_live": len(live), "controls_detected": detected,
               "controls_unreached": len(crow) - len(live), "equivalent_mutants": len(equiv),
               "coverage": {name: [hit, total] for name, _, total, hit in cov}}
    (out / "summary.json").write_text(json.dumps(summary, indent=1, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": len(cases), "negative_controls": len(live),
                                                    "negative_detected": detected}, sort_keys=True) + "\n")
    return summary


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, type=pathlib.Path)
    args = ap.parse_args(argv)
    try:
        s = generate(args.out)
    except ToolError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps({k: s[k] for k in ("cases", "mismatches", "controls_live", "controls_detected")}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
