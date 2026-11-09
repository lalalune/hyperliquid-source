#!/usr/bin/env python3
"""Reconstruct and validate the node #115 Vec<u8> serializer leaves behind the state-export routers.

Nine bodies write serde_json / rmp text into a growable byte vector (cap +0x0, ptr +0x8, len +0x10): the
amortised grow 0x4787e90 with its reallocator 0x4787da0, two u64 decimal formatters (0x4779320, 0x4301950: 20-byte
scratch, two-digit pair table), the JSON string-escape writer 0x4778320, the compact map entry 0x4777ad0, the
pretty-printed struct field 0x4777cc0 and its one-field struct driver 0x4783f20, the rmp unsigned-integer writer
0x47789c0 (fixint / 0xcc / 0xcd / 0xce / 0xcf with io-error results) and the JSON array-of-records writer 0x4776de0
(its element writer 0x4781f10 and the f64 formatter behind .got 0x64e13d0 are stubs shared by model and code).
The tool reads every code byte, relocation, FDE extent and escape table from the ELF file and evaluates the real
machine code with the repository's concrete x86-64 evaluator (the binary is never executed).  One `Env` object
holds every callee behaviour (heap allocator, memcpy, panic stubs, f64 text) and is used both by the pure-Python
reconstruction and by the stubs the machine code calls, so heap addresses, capacities and call logs compare
directly.  Negative controls show that wrong reconstructions and corrupted code bytes are caught.
Role names (state-export writer, compact/pretty serializer) are inferences; the byte behaviour is observed.
"""
import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import re16_state_compose115 as ev  # noqa: E402

Image, Boundary, ToolError, Stream = ev.Image, ev.Boundary, ev.ToolError, ev.Stream
BINARY, SHA256, M64 = ev.BINARY, ev.SHA256, ev.M64
fail = ev.fail

HEAP_AT, HEAP_SIZE = 0x2000_0000, 0x4000
IN_AT, IN_SIZE = 0x3000_0000, 0x400
ST_AT, ST_SIZE = 0x4000_0000, 0x400
VEC, SER, CMP, VAL, OUT, BUF, WR, ENTV = (ST_AT + x for x in (0x00, 0x30, 0x40, 0x60, 0x80, 0xa0, 0xd0, 0xe0))
PSER = ST_AT + 0x100
KEY, INDENT, ENTRIES = IN_AT, IN_AT + 0x100, IN_AT + 0x200
HEAP_FILL, IN_FILL, ST_FILL = 0xa5, 0x5a, 0x3c
JUNK = 0x1badc0de1badc0de
SAVED = {3: 0x1111111111111111, 5: 0x2222222222222222, 12: 0x3333333333333333, 13: 0x4444444444444444,
         14: 0x5555555555555555, 15: 0x6666666666666666}
IOERR = 0x2600000003
STACK_LO, STACK_HI = ev.STACK_TOP - 0x10000, ev.STACK_TOP

# GOT slot -> role.  Every slot is a RELATIVE or GLOB_DAT relocation; the evaluator keys stubs by the target.
SLOTS = {0x64df508: "memcpy", 0x64df498: "alloc_handler", 0x64df520: "overflow_a", 0x64df848: "overflow_b",
         0x64df730: "panic_str", 0x64df580: "realloc_aligned", 0x64df588: "realloc", 0x64df590: "malloc_aligned",
         0x64df480: "malloc", 0x64e13d0: "fmt_f64"}
ELEM_CALL = 0x4781f10
ESC_SLOT, HEX_SLOT = 0x64e13d8, 0x64e13e0
PRETTY_KEY_AT, PRETTY_KEY_LEN = 0x7e1c4f, 0x1b
PAIR_TABLES = (0x7e17d6, 0x7c9625)
PANIC_STR_ARGS = (0x7e178d, 0x28, 0x6496cc0)
OVERFLOW_A_ARG = 0x6497608
FUNCS = {"grow": 0x4787e90, "itoa_a": 0x4779320, "itoa_b": 0x4301950, "escape": 0x4778320, "entry": 0x4777ad0,
         "field": 0x4777cc0, "struct1": 0x4783f20, "rmp_uint": 0x47789c0, "array": 0x4776de0}
EXTRA_FDES = (0x4787da0,)


class Panic(Exception):
    def __init__(self, kind, a=None, b=None, c=None):
        super().__init__(kind)
        self.t = (kind, a, b, c)


class Tables:
    def __init__(self, image):
        self.esc = image.read(image.relative[ESC_SLOT], 256)
        self.hexd = image.read(image.relative[HEX_SLOT], 16)
        self.pretty_key = image.read(PRETTY_KEY_AT, PRETTY_KEY_LEN)
        self.image = image


# ---------------------------------------------------------------- shared callee behaviour
class Env:
    """Memory, allocator and every callee; used by the model directly and by machine stubs."""

    def __init__(self, spec, tables, mut=frozenset()):
        self.spec, self.tables, self.mut = spec, tables, mut
        self.heap = bytearray([HEAP_FILL]) * HEAP_SIZE
        self.inp = bytearray([IN_FILL]) * IN_SIZE
        self.st = bytearray([ST_FILL]) * ST_SIZE
        data = spec.get("in", b"")
        self.inp[:len(data)] = data
        self.regions = [(HEAP_AT, HEAP_AT + HEAP_SIZE, self.heap), (IN_AT, IN_AT + IN_SIZE, self.inp),
                        (ST_AT, ST_AT + ST_SIZE, self.st)]
        self.top, self.blocks, self.log, self.nalloc, self.fail_after = 16, {}, [], 0, None
        v = spec.get("vec")
        if v:
            cap, data = v["cap"], v["data"]
            if v.get("fake"):
                ptr = HEAP_AT + 0x3000
            elif cap == 0:
                ptr = 1
            else:
                ptr = self._alloc(cap)
                self.wr(ptr, data)
            self.wr64(VEC, cap), self.wr64(VEC + 8, ptr), self.wr64(VEC + 16, v["len"])
            self.wr64(SER, VEC), self.wr64(WR, VEC), self.wr64(PSER, VEC)
        self.fail_after = spec.get("fail_after")
        for off, blob in spec.get("st", {}).items():
            self.wr(ST_AT + off, blob)

    # --- raw memory (regions, then file-backed read-only data)
    def find(self, at, n):
        for lo, hi, buf in self.regions:
            if lo <= at and at + n <= hi:
                return buf, at - lo
        return None, None

    def rd(self, at, n):
        buf, o = self.find(at, n)
        if buf is None:
            return self.tables.image.read(at, n)
        return bytes(buf[o:o + n])

    def wr(self, at, blob):
        buf, o = self.find(at, len(blob))
        if buf is None:
            fail(f"write outside regions at {at:#x}")
        buf[o:o + len(blob)] = blob

    def rd64(self, at):
        return int.from_bytes(self.rd(at, 8), "little")

    def wr64(self, at, v):
        self.wr(at, (v & M64).to_bytes(8, "little"))

    # --- allocator
    def _alloc(self, n):
        n = max(n, 1)
        if self.top + n > HEAP_SIZE:
            return 0
        ptr = HEAP_AT + self.top
        self.top = (self.top + n + 15) & ~15
        self.blocks[ptr] = n
        return ptr

    def _fails(self):
        idx = self.nalloc
        self.nalloc += 1
        return self.fail_after is not None and idx >= self.fail_after

    def alloc(self, n, tag="malloc", extra=None):
        self.log.append((tag, n) if extra is None else (tag, n, extra))
        return 0 if self._fails() else self._alloc(n)

    def realloc(self, ptr, n, tag="realloc", extra=None):
        off = ptr - HEAP_AT if HEAP_AT <= ptr < HEAP_AT + HEAP_SIZE else ptr
        self.log.append((tag, off, n) if extra is None else (tag, off, n, extra))
        if self._fails():
            return 0
        new = self._alloc(n)
        if new:
            k = min(self.blocks.get(ptr, 0), n)
            if k:
                self.wr(new, self.rd(ptr, k))
        return new

    def memcpy(self, dst, src, n, data=None, tag=None):
        if data is None:
            data = self.rd(src, n)
        self.log.append(("memcpy", dst, tag if tag is not None else src, n, data))
        if n:
            self.wr(dst, data)
        return dst

    def f64_text(self, bits):
        self.log.append(("fmt_f64", bits))
        return repr(struct.unpack("<d", bits.to_bytes(8, "little"))[0]).encode()

    def elem(self, entry, ser):
        """Stub of the per-record element writer 0x4781f10: appends '"e', the entry's first byte and '"'."""
        self.log.append(("elem", entry, ser))
        self.vec_append(self.rd64(ser), b'"e' + self.rd(entry, 1) + b'"')
        return self.spec.get("elem_ret", 0)

    # --- Vec<u8> behaviour (the asm patterns)
    def vec_append(self, vec, blob):
        n = len(blob)
        cap, ln = self.rd64(vec), self.rd64(vec + 16)
        if cap - ln < n:
            self.grow(vec, ln, n, 1, 1)
        ptr, ln = self.rd64(vec + 8), self.rd64(vec + 16)
        self.wr(ptr + ln, blob)
        self.wr64(vec + 16, ln + n)

    def raw_alloc(self, cap, ptr, count, align, elem):
        """0x4787da0: ("ok", ptr), ("err1",) or ("err2", align, bytes)."""
        prod = elem * count
        nbytes = prod & M64
        if prod >> 64 or nbytes > (1 << 63) - align:
            return ("err1",)
        tz = (align & -align).bit_length() - 1 if align else 64
        plain = (align < 0x11 and align <= nbytes) or tz == 0
        if "grow_ignore_align" in self.mut:
            plain = True
        if cap:
            new = self.realloc(ptr, nbytes) if plain else self.realloc(ptr, nbytes, "realloc_aligned", tz)
        elif nbytes == 0:
            return ("ok", align)
        else:
            new = self.alloc(nbytes) if plain else self.alloc(nbytes, "malloc_aligned", tz)
        if new == 0:
            return ("err2", align, nbytes)
        return ("ok", new)

    def grow(self, vec, ln, add, align, elem):
        """0x4787e90 (RawVec at vec: cap +0, ptr +8)."""
        if elem == 0:
            raise Panic("alloc_handler", 0)
        need = ln + add
        if need > M64:
            raise Panic("alloc_handler", 0)
        cap = self.rd64(vec)
        rax = need if "grow_no_doubling" in self.mut else max((2 * cap) & M64, need)
        minnz = 8 if elem == 1 else (4 if elem < 0x401 else 1)
        if "grow_min_four" in self.mut and elem == 1:
            minnz = 4
        newcap = max(rax, minnz)
        r = self.raw_alloc(cap, self.rd64(vec + 8), newcap, align, elem)
        if r[0] == "err1":
            raise Panic("alloc_handler", 0)
        if r[0] == "err2":
            raise Panic("alloc_handler", r[1], r[2])
        self.wr64(vec + 8, r[1])
        self.wr64(vec, newcap)

    def inline_grow(self, vec, cap_old, need=None):
        """Inline `lea rax,[2*x]; cmova need; cmp rax,9; cmovae` + 0x4787da0; True on success."""
        rax = (2 * cap_old) & M64
        if need is not None and need > rax:
            rax = need
        newcap = rax if rax >= 9 else 8
        r = self.raw_alloc(cap_old, self.rd64(vec + 8), newcap, 1, 1)
        if r[0] != "ok":
            return False
        self.wr64(vec + 8, r[1])
        self.wr64(vec, newcap)
        return True


# ---------------------------------------------------------------- pure-Python reconstruction
def digits(env, v):
    text = str(v).encode()
    if "itoa_drop_last" in env.mut and len(text) > 1:
        text = text[:-1]
    return text


def model_itoa(env, p):
    text = digits(env, p["v"])
    env.wr(BUF + 20 - len(text), text)
    return (BUF + 20 - len(text), len(text))


def push_byte(env, vec, b):
    cap, ln = env.rd64(vec), env.rd64(vec + 16)
    if cap == ln:
        env.grow(vec, ln, 1, 1, 1)
        ln = env.rd64(vec + 16)
    env.wr(env.rd64(vec + 8) + ln, bytes([b]))
    env.wr64(vec + 16, ln + 1)


def push_run(env, vec, src, n, data=None, tag=None):
    cap, ln = env.rd64(vec), env.rd64(vec + 16)
    if cap - ln < n:
        env.grow(vec, ln, n, 1, 1)
        ln = env.rd64(vec + 16)
    env.memcpy(env.rd64(vec + 8) + ln, src, n, data, tag)
    env.wr64(vec + 16, ln + n)


def push_text(env, vec, blob):
    """A short literal store: one capacity test (room <= n-1 grows by n) then one store."""
    n = len(blob)
    cap, ln = env.rd64(vec), env.rd64(vec + 16)
    if cap - ln <= n - 1:
        env.grow(vec, ln, n, 1, 1)
        ln = env.rd64(vec + 16)
    env.wr(env.rd64(vec + 8) + ln, blob)
    env.wr64(vec + 16, ln + n)


def push_digits(env, vec, v):
    text = digits(env, v)
    push_run(env, vec, 0, len(text), text, "stack")


def escape_str(env, vec, src, n):
    esc, hexd = env.tables.esc, env.tables.hexd
    if "escape_upper_hex" in env.mut:
        hexd = hexd.upper()
    start = 0
    for i in range(n):
        b = env.rd(src + i, 1)[0]
        code = esc[b]
        if "escape_slash" in env.mut and b == 0x2f:
            code = 0x2f
        if code == 0:
            continue
        if i > start:
            push_run(env, vec, src + start, i - start)
        if code == 0x75:
            push_text(env, vec, b"\\u00" + bytes([hexd[b >> 4], hexd[b & 15]]))
        else:
            push_text(env, vec, b"\\" + bytes([code]))
        start = i + 1
    if n > start:
        push_run(env, vec, src + start, n - start)


def model_escape(env, p):
    escape_str(env, VEC, p.get("kaddr", KEY), p["klen"])
    return None


def model_grow(env, p):
    env.grow(VEC, p["len"], p["add"], p["align"], p["elem"])
    return None


def entry_core(env, flag, state, ser, kaddr, klen, value, setstate):
    if flag == 1:
        raise Panic("panic_str", *PANIC_STR_ARGS)
    vec = env.rd64(ser)
    if state != 1 or "entry_comma_always" in env.mut:
        push_byte(env, vec, 0x2c)
    setstate(1 if "entry_state_stuck" in env.mut else 2)
    push_byte(env, vec, 0x22)
    escape_str(env, vec, kaddr, klen)
    push_byte(env, vec, 0x22)
    push_byte(env, vec, 0x3a)
    push_digits(env, vec, value)
    return 0


def setcmp(env):
    return lambda s: env.wr(CMP + 1, bytes([s]))


def model_entry(env, p):
    flag, state = env.rd(CMP, 2)
    return entry_core(env, flag, state, env.rd64(CMP + 8), p.get("kaddr", KEY), p["klen"], env.rd64(VAL),
                      setcmp(env))


def pretty_indent(env, vec, pser):
    depth, ilen, iptr = env.rd64(pser + 0x18), env.rd64(pser + 0x10), env.rd64(pser + 8)
    if "field_indent_once" in env.mut:
        depth = min(depth, 1)
    if ilen == 0:
        return
    for _ in range(depth):
        push_run(env, vec, iptr, ilen)


def field_core(env, flag, state, pser, kaddr, klen, value, setstate):
    if flag == 1:
        raise Panic("panic_str", *PANIC_STR_ARGS)
    vec = env.rd64(pser)
    first = b"\n" if state == 1 else b",\n"
    if "field_swap_sep" in env.mut:
        first = b",\n" if state == 1 else b"\n"
    push_text(env, vec, first)
    pretty_indent(env, vec, pser)
    setstate(2)
    push_byte(env, vec, 0x22)
    escape_str(env, vec, kaddr, klen)
    push_byte(env, vec, 0x22)
    push_text(env, vec, b":" if "field_colon_tight" in env.mut else b": ")
    push_digits(env, vec, value)
    env.wr(pser + 0x20, b"\x01")
    return 0


def model_field(env, p):
    flag, state = env.rd(CMP, 2)
    return field_core(env, flag, state, env.rd64(CMP + 8), p.get("kaddr", KEY), p["klen"], env.rd64(VAL), setcmp(env))


def model_struct1(env, p):
    depth = env.rd64(PSER + 0x18)
    if depth == M64:
        raise Panic("overflow_a", OVERFLOW_A_ARG)
    vec = env.rd64(PSER)
    env.wr64(PSER + 0x18, depth + 1)
    env.wr(PSER + 0x20, b"\x00")
    push_text(env, vec, b"{")
    stack = {"state": 1}
    rax = field_core(env, 0, 1, PSER, PRETTY_KEY_AT, PRETTY_KEY_LEN, env.rd64(VAL), lambda s: stack.update(state=s))
    if rax or not stack["state"]:
        return rax
    if "struct1_depth_kept" not in env.mut:
        env.wr64(PSER + 0x18, env.rd64(PSER + 0x18) - 1)
    if env.rd(PSER + 0x20, 1)[0]:
        push_text(env, vec, b"\n")
        pretty_indent(env, vec, PSER)
    push_text(env, vec, b"}")
    return 0


def model_rmp(env, p):
    v = p["v"]
    vec = env.rd64(WR)
    out = OUT

    def tagerr(tag):
        env.wr64(out, tag)
        env.wr64(out + 8, IOERR)

    def marker(m):
        cap, ln = env.rd64(vec), env.rd64(vec + 16)
        if cap == ln:
            if not env.inline_grow(vec, ln):
                return False
            if env.rd64(vec) == env.rd64(vec + 16):
                env.grow(vec, env.rd64(vec + 16), 1, 1, 1)
        ln = env.rd64(vec + 16)
        env.wr(env.rd64(vec + 8) + ln, bytes([m]))
        env.wr64(vec + 16, ln + 1)
        return True

    fix_limit = 0xff if "rmp_fix_limit_ff" in env.mut else 0x80
    if v < fix_limit:
        if not marker(v):
            return tagerr(0)
        env.wr(out + 8, b"\x00" + bytes([v]))
        env.wr64(out, 2)
        return None
    if v < 0x100:
        if not marker(0xcc):
            return tagerr(0)
        cap, ln = env.rd64(vec), env.rd64(vec + 16)
        if cap == ln:
            if not env.inline_grow(vec, ln, (ln + 1) & M64):
                return tagerr(1)
            if env.rd64(vec) == env.rd64(vec + 16):
                env.grow(vec, env.rd64(vec + 16), 1, 1, 1)
        ln = env.rd64(vec + 16)
        env.wr(env.rd64(vec + 8) + ln, bytes([v]))
        env.wr64(vec + 16, ln + 1)
        env.wr64(out, 2)
        env.wr64(out + 8, 0xcc)
        return None
    size, mk = (2, 0xcd) if v < 0x10000 else ((4, 0xce) if v < 1 << 32 else (8, 0xcf))
    if "rmp_ce_as_cd" in env.mut and mk == 0xce:
        size, mk = 2, 0xcd
    if not marker(mk):
        return tagerr(0)
    cap, ln = env.rd64(vec), env.rd64(vec + 16)
    if cap - ln <= size - 1:
        total = (ln - 1 + size + 1) & M64
        if total < ln:
            return tagerr(1)
        if not env.inline_grow(vec, cap, total):
            return tagerr(0 if "rmp_err_tag" in env.mut else 1)
        ln = env.rd64(vec + 16)
        if env.rd64(vec) - ln <= size - 1:
            env.grow(vec, ln, size, 1, 1)
    ln = env.rd64(vec + 16)
    payload = (v & ((1 << (8 * size)) - 1)).to_bytes(size, "little" if "rmp_little_endian" in env.mut else "big")
    env.wr(env.rd64(vec + 8) + ln, payload)
    env.wr64(vec + 16, ln + size)
    env.wr64(out, 2)
    env.wr64(out + 8, mk)
    return None


def f64_field(env, vec, bits):
    limit = 0x7ff0000000000000 if "array_inf_as_finite" in env.mut else 0x7fefffffffffffff
    if (bits & 0x7fffffffffffffff) > limit:
        push_text(env, vec, b"null")
        return
    text = env.f64_text(bits)
    push_run(env, vec, 0, len(text), text, "stack")


def model_array(env, p):
    vec = env.rd64(SER)
    ptr, n = env.rd64(ENTV + 8), env.rd64(ENTV + 16)
    push_byte(env, vec, 0x5b)
    if n == 0:
        push_byte(env, vec, 0x5d)
        return 0
    for i in range(n):
        e = ptr + 32 * i
        if i and "array_no_record_comma" not in env.mut:
            push_byte(env, vec, 0x2c)
        push_byte(env, vec, 0x5b)
        rax = env.elem(e, SER)
        if rax:
            return rax
        for off in (8, 0x10):
            push_byte(env, vec, 0x2c)
            push_digits(env, vec, env.rd64(e + off))
        push_byte(env, vec, 0x2c)
        f64_field(env, vec, env.rd64(e + 0x18))
        push_byte(env, vec, 0x5d)
    push_byte(env, vec, 0x5d)
    return 0


MODELS = {"grow": model_grow, "itoa_a": model_itoa, "itoa_b": model_itoa, "escape": model_escape,
          "entry": model_entry, "field": model_field, "struct1": model_struct1, "rmp_uint": model_rmp,
          "array": model_array}


# ---------------------------------------------------------------- machine side
def decode2(code, va):
    """The repository decoder plus the two encodings it lacks: `66 c7` (16-bit immediate) and `66 0f d6` (movq store)."""
    code = bytes(code)
    if code[0] == 0x66:
        j = 2 if 0x40 <= code[1] <= 0x4f else 1
        if code[j] == 0xc7:
            f = ev.decode(code[1:] + b"\0\0", va + 1)
            f["imm"] &= 0xffff
            f["size"] = 16
            f["len"] -= 1  # one prefix byte more, two immediate bytes fewer than the 32-bit decode
            f["bytes"] = code[:f["len"]]
            return f
        if code[j] == 0x0f and code[j + 1] == 0xd6:
            ba = bytearray(code)
            ba[j + 1] = 0x29
            f = ev.decode(bytes(ba), va)
            f["op"] = 0xfd6
            return f
    return ev.decode(code, va)


class Mach(ev.Machine):
    def fetch(self, va):
        form = self.cache.get(va)
        if form is None:
            code = bytearray(self.image.code(va, 16))
            for i in range(16):
                if va + i in self.override:
                    code[i] = self.override[va + i]
            form = decode2(bytes(code), va)
            self.cache[va] = form
        return form

    def step(self, va):
        f = self.fetch(va)
        op = f["op"]
        nxt = (va + f["len"]) & M64
        if op == 0xfd6:
            self.store(self.ea(f["rm"], f, va), 8, self.xmm[f["reg"]] & M64)
            return nxt
        if op == 0x0f7e and f["rep"]:  # movq xmm, r/m64
            rm = f["rm"]
            self.xmm[f["reg"]] = self.xmm[rm[1]] & M64 if rm[0] == "r" else self.load(self.ea(rm, f, va), 8)
            return nxt
        return super().step(va)

    def load_bytes(self, at, size):
        for lo, hi, buf in self.regions:
            if lo <= at and at + size <= hi:
                return bytes(buf[at - lo:at - lo + size])
        return self.image.read(at, size)

    def store_bytes(self, at, blob):
        for lo, hi, buf in self.regions:
            if lo <= at and at + len(blob) <= hi:
                buf[at - lo:at - lo + len(blob)] = blob
                return
        fail(f"byte write outside regions at {at:#x}")


def clobber(m, ret):
    for r in (1, 2, 6, 7, 8, 9, 10, 11):
        m.regs[r] = JUNK
    m.regs[0] = ret
    m.xmm = [JUNK | JUNK << 64] * 16


def install(m, env, img):
    rel = img.relative

    def memcpy(mm):
        dst, src, n = mm.regs[7], mm.regs[6], mm.regs[2]
        if STACK_LO <= src < STACK_HI:
            env.memcpy(dst, src, n, mm.load_bytes(src, n), "stack")
        else:
            env.memcpy(dst, src, n)
        clobber(mm, dst)

    def malloc(mm):
        clobber(mm, env.alloc(mm.regs[7]))

    def malloc_aligned(mm):
        clobber(mm, env.alloc(mm.regs[7], "malloc_aligned", mm.regs[6]))

    def realloc(mm):
        clobber(mm, env.realloc(mm.regs[7], mm.regs[6]))

    def realloc_aligned(mm):
        clobber(mm, env.realloc(mm.regs[7], mm.regs[6], "realloc_aligned", mm.regs[2]))

    def fmt(mm):
        text = env.f64_text(mm.xmm[0] & M64)
        mm.store_bytes(mm.regs[7], text)
        clobber(mm, mm.regs[7] + len(text))

    def elem(mm):
        clobber(mm, env.elem(mm.regs[7], mm.regs[6]))

    for slot, role in SLOTS.items():
        if slot not in rel:
            fail(f"slot {slot:#x} has no relocation")
    m.stubs[rel[0x64df508]] = memcpy
    m.stubs[rel[0x64df480]] = malloc
    m.stubs[rel[0x64df590]] = malloc_aligned
    m.stubs[rel[0x64df588]] = realloc
    m.stubs[rel[0x64df580]] = realloc_aligned
    m.stubs[rel[0x64e13d0]] = fmt
    m.stubs[ELEM_CALL] = elem
    for slot in (0x64df498, 0x64df520, 0x64df848, 0x64df730):
        m.stubs[rel[slot]] = SLOTS[slot]


ARGS = {  # register index -> value builder
    "grow": lambda p: {7: VEC, 6: p["len"], 2: p["add"], 1: p["align"], 8: p["elem"]},
    "itoa_a": lambda p: {7: p["v"], 6: BUF},
    "itoa_b": lambda p: {7: p["v"], 6: BUF},
    "escape": lambda p: {7: VEC, 6: p.get("kaddr", KEY), 2: p["klen"]},
    "entry": lambda p: {7: CMP, 6: p.get("kaddr", KEY), 2: p["klen"], 1: VAL},
    "field": lambda p: {7: CMP, 6: p.get("kaddr", KEY), 2: p["klen"], 1: VAL},
    "struct1": lambda p: {7: VAL, 6: PSER},
    "rmp_uint": lambda p: {7: OUT, 6: WR, 2: p["v"]},
    "array": lambda p: {7: SER, 6: ENTV},
}
RETS = {"itoa_a": "pair", "itoa_b": "pair", "entry": "rax", "field": "rax", "struct1": "rax", "array": "rax"}


def panic_norm(kind, rdi, rsi, rdx):
    if kind == "alloc_handler":
        return (kind, rdi, rsi if rdi else None, None)
    if kind == "overflow_a":
        return (kind, rdi, None, None)
    return (kind, rdi, rsi, rdx)


def digest_env(env, panic, ret):
    return {"mem": (bytes(env.heap[:env.top + 16]), bytes(env.inp), bytes(env.st)), "log": list(env.log),
            "panic": panic, "ret": ret}


def run_model(spec, tables, mut=frozenset()):
    env = Env(spec, tables, mut)
    panic = ret = None
    try:
        ret = MODELS[spec["fn"]](env, spec)
    except Panic as exc:
        panic = exc.t
    kind = RETS.get(spec["fn"])
    if kind == "rax" and ret is not None:
        ret = (ret & M64,)
    return digest_env(env, panic, ret if panic is None else None)


def run_machine(m, spec, tables, img):
    env = Env(spec, tables)
    m.reset()
    install(m, env, img)
    for region in env.regions:
        m.regions.append(region)
    for k, v in SAVED.items():
        m.regs[k] = v
    entry_sp = m.regs[4]
    for r, v in ARGS[spec["fn"]](spec).items():
        m.regs[r] = v
    panic = None
    try:
        m.run(FUNCS[spec["fn"]], limit=60000)
    except Boundary as exc:
        regs = exc.regs
        panic = panic_norm(exc.kind, regs[7], regs[6], regs[2])
    except Panic as exc:  # a shared callee (the element stub) panicked inside the machine run
        panic = exc.t
    except (ToolError, KeyError) as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}
    kind = RETS.get(spec["fn"])
    ret = None
    if panic is None:
        ret = (m.regs[0], m.regs[2]) if kind == "pair" else ((m.regs[0],) if kind == "rax" else None)
        if kind == "pair":
            ret = (m.regs[0], m.regs[2])
    out = digest_env(env, panic, ret)
    out["regs_ok"] = panic is not None or (all(m.regs[k] == v for k, v in SAVED.items()) and m.regs[4] == entry_sp)
    return out


def same(want, got):
    if "error" in got:
        return False
    if got["panic"] is None and not got["regs_ok"]:
        return False
    if want["panic"] != got["panic"] or want["ret"] != got["ret"] or want["log"] != got["log"]:
        return False
    if want["mem"][1] != got["mem"][1] or want["mem"][0] != got["mem"][0]:
        return False
    if want["mem"][2] != got["mem"][2]:
        return False
    return True


# ---------------------------------------------------------------- cases
PER_FN = {"grow": 1700, "itoa_a": 900, "itoa_b": 900, "escape": 1700, "entry": 1500, "field": 1500, "struct1": 900,
          "rmp_uint": 2400, "array": 1500}
ORDER = ("grow", "itoa_a", "itoa_b", "escape", "entry", "field", "struct1", "rmp_uint", "array")
SPECIAL = [0, 1, 9, 10, 99, 100, 999, 1000, 9999, 10000, 99999, 100000, 99999999, 100000000, 4294967295, 4294967296,
           10 ** 15, 10 ** 19 - 1, 10 ** 19, M64, M64 - 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0x7fffffffffffffff]


def rnd_u64(s, bias=None):
    k = s.below(20) + 1 if bias is None else bias
    return int.from_bytes(s.take(8), "little") % (10 ** k) if k < 20 else int.from_bytes(s.take(8), "little")


def pick_u64(s):
    return s.pick(SPECIAL) if s.below(6) == 0 else rnd_u64(s)


def gen_vec(s, i, need):
    mode = i % 9
    ln = s.below(12) if mode != 0 else 0
    if mode == 0:
        cap = ln = 0
    elif mode == 1:
        cap = ln
    elif mode == 2:
        cap = ln + 8 + s.below(32)
    elif mode == 3:
        cap = ln + max(need - 1, 0)
    elif mode == 4:
        cap = ln + need
    elif mode == 5:
        cap = ln + need + 1
    elif mode == 6:
        cap = ln + s.below(4)
    elif mode == 7:
        cap, ln = s.below(40), 0
        ln = s.below(cap + 1)
    else:
        cap = ln + s.below(3) * need
    vec = {"cap": cap, "len": ln, "data": s.take(cap)[:cap] if cap else b""}
    fa = None
    r = s.below(24)
    if r < 2:
        fa = r
    elif r == 2:
        fa = 2 + s.below(2)
    return vec, fa


def key_bytes(s, n):
    raw = bytearray(s.take(n))
    spec = [0x22, 0x5c, 0x0a, 0x09, 0x0d, 0x08, 0x0c, 0x01, 0x1f, 0x00, 0x2f, 0x7f, 0x80, 0xff, 0x20]
    mode = s.below(5)
    for j in range(n):
        if mode == 0:
            raw[j] = 0x61 + raw[j] % 26
        elif mode == 1:
            raw[j] = s.pick(spec) if raw[j] & 3 == 0 else 0x61 + raw[j] % 26
        elif mode == 2:
            raw[j] = s.pick(spec)
        elif mode == 3:
            raw[j] = raw[j] if raw[j] & 7 == 0 else 0x30 + raw[j] % 40
    return bytes(raw)


def make_case(s, fn, i):
    p = {"fn": fn, "i": i}
    if fn == "grow":
        add = s.pick([0, 1, 1, 2, 3, 5, 8, 9, 17, 100, 300, s.below(2000)])
        align = s.pick([1, 1, 1, 2, 4, 8, 16, 32, 64, 4096])
        elem = s.pick([1, 1, 1, 1, 2, 8, 24, 1024, 1025, 4096, 0 if s.below(8) == 0 else 1])
        p.update(add=add, align=align, elem=elem)
        vec, fa = gen_vec(s, i, add)
        if i % 47 == 5:
            vec = {"cap": 1 << 62, "len": 1 << 62, "data": b"", "fake": True}
            p["add"] = s.pick([1, 5, 1 << 62])
        elif i % 47 == 6:
            vec = {"cap": M64 - 3, "len": M64 - 3, "data": b"", "fake": True}
            p["add"] = s.pick([1, 4, 5, 9])
        elif i % 47 == 7:
            vec = {"cap": 1 << 63, "len": 7, "data": b"", "fake": True}
        p["len"] = vec["len"] if s.below(6) else s.below(40)
        p["vec"], p["fail_after"] = vec, fa
    elif fn in ("itoa_a", "itoa_b"):
        p["v"] = pick_u64(s)
        p["st"] = {0xa0: s.take(24)}
    elif fn in ("escape", "entry", "field"):
        n = s.pick([0, 1, 2, 3, 5, 8, 12, 20, 33, 40, s.below(41)])
        p["klen"] = n
        p["in"] = key_bytes(s, n)
        need = n + 2
        vec, fa = gen_vec(s, i, need if fn == "escape" else s.pick([1, 2, 3, 6, need]))
        p["vec"], p["fail_after"] = vec, fa
        if fn != "escape":
            st = {0x40: bytes([1 if s.below(40) == 0 else 0, s.pick([0, 1, 1, 2, 2]) if s.below(5) else 1]),
                  0x48: SER.to_bytes(8, "little") if fn == "entry" else PSER.to_bytes(8, "little"),
                  0x60: pick_u64(s).to_bytes(8, "little")}
            p["st"] = st
        if fn == "field":
            ilen = s.pick([0, 1, 2, 4, 3])
            depth = s.pick([0, 1, 2, 3, 4, 1, 2])
            p["st"][0x108] = INDENT.to_bytes(8, "little") + ilen.to_bytes(8, "little") + depth.to_bytes(8, "little") \
                + bytes([s.below(2)])
            p["in"] = p["in"].ljust(0x100, b"\x5a") + s.take(8)
    elif fn == "struct1":
        vec, fa = gen_vec(s, i, s.pick([1, 2, 3, 28, 30, 34]))
        p["vec"], p["fail_after"] = vec, fa
        ilen = s.pick([0, 1, 2, 4, 3])
        depth = s.pick([0, 1, 2, 3, 4]) if i % 31 != 3 else M64
        p["st"] = {0x60: pick_u64(s).to_bytes(8, "little"),
                   0x108: INDENT.to_bytes(8, "little") + ilen.to_bytes(8, "little") + depth.to_bytes(8, "little")
                   + bytes([s.below(2)])}
        p["in"] = bytes(0x100) + s.take(8)
    elif fn == "rmp_uint":
        v = s.pick([0, 1, 0x7f, 0x80, 0xff, 0x100, 0xffff, 0x10000, 0xffffffff, 0x100000000, M64]) \
            if s.below(4) == 0 else int.from_bytes(s.take(8), "little") >> s.pick([0, 8, 24, 40, 56, 57])
        p["v"] = v
        size = 0 if v < 0x80 else (1 if v < 0x100 else (2 if v < 0x10000 else (4 if v < 1 << 32 else 8)))
        vec, fa = gen_vec(s, i, size + 2)
        if i % 53 == 9:
            big = s.pick([M64 - 1, 1 << 62, M64 - 7])
            vec = {"cap": big, "len": big, "data": b"", "fake": True}
        p["vec"], p["fail_after"] = vec, fa
    elif fn == "array":
        n = s.pick([0, 1, 2, 3, 4, 2, 3])
        ents = bytearray()
        for _ in range(n):
            bits = s.pick([0, 0x8000000000000000, 0x7fefffffffffffff, 0x7ff0000000000000, 0xfff0000000000000,
                           0x7ff8000000000001, 1, 0x3ff0000000000000, 0xc000000000000000]) if s.below(2) \
                else int.from_bytes(s.take(8), "little") & 0x7fefffffffffffff | s.below(2) << 63
            ents += s.take(8) + pick_u64(s).to_bytes(8, "little") + pick_u64(s).to_bytes(8, "little") + bits.to_bytes(8, "little")
        p["in"] = bytes(0x200) + bytes(ents)
        p["st"] = {0xe0: (4).to_bytes(8, "little") + ENTRIES.to_bytes(8, "little") + n.to_bytes(8, "little")}
        vec, fa = gen_vec(s, i, s.pick([1, 4, 8, 12, 40]))
        p["vec"], p["fail_after"] = vec, fa
        p["elem_ret"] = 0 if s.below(12) else 0x55
    return p


def fn_cases(fn):
    s = Stream("re009-vec-writer-" + fn)
    for i in range(PER_FN[fn]):
        yield make_case(s, fn, i)


def all_cases():
    for fn in ORDER:
        yield from fn_cases(fn)


def outcome(want, fn=None):
    if want["panic"]:
        return "panic:" + want["panic"][0]
    if fn == "rmp_uint":
        tag = want["mem"][2][OUT - ST_AT]
        return "ok" if tag == 2 else f"io-error-tag-{tag}"
    return "ok"


def evaluate(img, tables, mut=frozenset(), override=None, stop_on_first=False, cases=None, machine=None):
    m = machine or Mach(img, override)
    total = bad = 0
    rows = []
    for p in (cases if cases is not None else all_cases()):
        want = run_model(p, tables, mut)
        got = run_machine(m, p, tables, img)
        ok = same(want, got)
        total += 1
        bad += not ok
        rows.append((p, want, got, ok))
        if stop_on_first and not ok:
            break
    return rows, bad, total


# ---------------------------------------------------------------- controls and static evidence
MODEL_MUTANTS = [
    ("grow", "grow_no_doubling"), ("grow", "grow_min_four"), ("grow", "grow_ignore_align"),
    ("itoa_a", "itoa_drop_last"), ("itoa_b", "itoa_drop_last"), ("escape", "escape_upper_hex"),
    ("escape", "escape_slash"), ("entry", "entry_comma_always"), ("entry", "entry_state_stuck"),
    ("field", "field_swap_sep"), ("field", "field_indent_once"), ("field", "field_colon_tight"),
    ("struct1", "struct1_depth_kept"), ("rmp_uint", "rmp_fix_limit_ff"), ("rmp_uint", "rmp_ce_as_cd"),
    ("rmp_uint", "rmp_err_tag"), ("rmp_uint", "rmp_little_endian"), ("array", "array_inf_as_finite"),
    ("array", "array_no_record_comma"), ("array", "itoa_drop_last"),
]


def cases_for(fn, limit=None):
    out = []
    for p in fn_cases(fn):
        out.append(p)
        if limit and len(out) >= limit:
            break
    return out


def function_rows(img, name_to_va):
    _, fdes = ev.fde_extents.eh_frame_records(img.data, img.secs)
    ext = {f["start"]: f["end"] for f in fdes}
    return {n: (va, ext[va]) for n, va in name_to_va.items()}


def sweep_rows(img, lo, hi):
    rows, va = [], lo
    while va < hi:
        f = decode2(img.code(va, 16), va)
        rows.append((va, f))
        va += f["len"]
    if va != hi:
        fail(f"linear decode overruns {hi:#x}")
    return rows


def branch_sites(img, fn_range):
    """Conditional-branch instructions of one function: (va, byte offset of the condition byte)."""
    out = []
    for va, f in sweep_rows(img, *fn_range):
        op = f["op"]
        if 0x70 <= op <= 0x7f:
            out.append((va, va))
        elif 0x0f80 <= op <= 0x0f8f:
            out.append((va, va + 1))
    return out


def byte_controls(img, tables, extents):
    rows = []
    for fn in ORDER:
        if fn == "itoa_b":
            continue
        cs = cases_for(fn, 700)
        sites = branch_sites(img, extents[fn])
        step = max(1, len(sites) // 9)
        tried = 0
        found = 0
        for k in range(step // 2, len(sites), step):
            va, at = sites[k]
            byte = img.code(at, 1)[0] ^ 1
            _, bad, _ = evaluate(img, tables, override={at: byte}, stop_on_first=True, cases=cs)
            tried += 1
            if bad:
                found += 1
                rows.append(("code", f"{fn} {va:#x}: condition byte {at:#x} {img.code(at, 1)[0]:#04x}->{byte:#04x}", 1))
            if found >= 3:
                break
        if not found:
            rows.append(("code", f"{fn}: {tried} branch inversions", 0))
    return rows


def input_controls(img):
    rows = []
    bad = bytearray(img.data)
    bad[img.text["offset"] + 7] ^= 1
    try:
        Image(bytes(bad))
        rows.append(("input", "one flipped .text byte", 0))
    except ToolError:
        rows.append(("input", "one flipped .text byte", 1))
    try:
        img.code(img.text["address"] + img.text["size"] + 0x100, 4)
        rows.append(("input", "address past .text", 0))
    except ToolError:
        rows.append(("input", "address past .text", 1))
    try:
        img.read(0x10, 4)
        rows.append(("input", "read below the first file-backed section", 0))
    except ToolError:
        rows.append(("input", "read below the first file-backed section", 1))
    return rows


def static_evidence(img, tables, extents):
    consts = {"binary_sha256": SHA256,
              "got_slots": {f"{s:#x}": {"role": r, "target": f"{img.relative[s]:#x}",
                                         "import": img.import_name(s) if s in img.imports else None}
                            for s, r in sorted(SLOTS.items())},
              "escape_table_nonzero": {f"{b:#04x}": f"{c:#04x}" for b, c in enumerate(tables.esc) if c},
              "hex_digits": tables.hexd.decode(), "pretty_key": tables.pretty_key.decode("latin-1"),
              "pretty_key_va": f"{PRETTY_KEY_AT:#x}",
              "pair_tables": {f"{a:#x}": img.read(a, 200) == b"".join(b"%02d" % i for i in range(100))
                              for a in PAIR_TABLES},
              "functions": {n: {"start": f"{a:#x}", "end": f"{b:#x}", "bytes": b - a} for n, (a, b) in sorted(extents.items())},
              "panic_str_literal": img.read(PANIC_STR_ARGS[0], PANIC_STR_ARGS[1]).decode("latin-1")}
    return consts


def caller_scan(img, targets):
    """Every `e8 rel32` byte pattern in .text whose target is one of `targets`, with the FDE that contains the site."""
    import bisect
    _, fdes = ev.fde_extents.eh_frame_records(img.data, img.secs)
    starts = sorted((f["start"], f["end"]) for f in fdes)
    keys = [s for s, _ in starts]
    text = img.text
    code = img.data[text["offset"]:text["offset"] + text["size"]]
    rows, p = [], code.find(b"\xe8")
    while p != -1 and p + 5 <= len(code):
        target = (text["address"] + p + 5 + struct.unpack_from("<i", code, p + 1)[0]) & M64
        if target in targets:
            site = text["address"] + p
            k = bisect.bisect_right(keys, site) - 1
            owner = starts[k][0] if k >= 0 and site < starts[k][1] else None
            rows.append((target, site, owner))
        p = code.find(b"\xe8", p + 1)
    return sorted(rows, key=lambda r: (r[0], r[1]))


def generate(out):
    img = Image(BINARY.read_bytes())
    tables = Tables(img)
    names = dict(FUNCS)
    names["realloc_4787da0"] = 0x4787da0
    extents = function_rows(img, names)
    out.mkdir(parents=True, exist_ok=True)
    seen = set()

    class Spy(Mach):
        def step(self, va):
            seen.add(va)
            return super().step(va)

    spy = Spy(img)
    rows, bad, total = evaluate(img, tables, machine=spy)
    classes = {}
    chain = hashlib.sha256()
    lines = ["case\tfunction\tparams\toutcome\tlog_len\tdigest\tmatch"]
    for p, want, got, ok in rows:
        cls = p["fn"] + "/" + outcome(want, p["fn"])
        classes[cls] = classes.get(cls, 0) + 1
        rec = repr((p["fn"], p["i"], want["panic"], want["ret"], want["log"], want["mem"])).encode()
        chain.update(hashlib.sha256(rec).digest())
        if len(lines) % 1 == 0 and (p["i"] % 4 == 0):
            vec = p.get("vec") or {}
            par = ",".join(f"{k}={p[k]:#x}" if isinstance(p[k], int) else f"{k}={len(p[k])}b"
                           for k in ("v", "add", "align", "elem", "klen", "len") if k in p)
            par += f",cap={vec.get('cap', 0):#x},vlen={vec.get('len', 0):#x},fail={p.get('fail_after')}" if vec else ""
            lines.append(f"{p['fn']}-{p['i']}\t{p['fn']}\t{par}\t{outcome(want, p['fn'])}\t{len(want['log'])}\t"
                         f"{hashlib.sha256(rec).hexdigest()[:16]}\t{'yes' if ok else 'NO'}")
    (out / "cases.tsv").write_text("\n".join(lines) + "\n")
    (out / "outcome-classes.tsv").write_text("outcome\tcases\n" + "".join(f"{k}\t{classes[k]}\n" for k in sorted(classes)))
    ins = ["function\taddress\tbytes\texecuted"]
    cov = {}
    for n, (lo, hi) in sorted(extents.items()):
        for va, f in sweep_rows(img, lo, hi):
            run = int(va in seen)
            cov.setdefault(n, [0, 0])
            cov[n][0] += run
            cov[n][1] += 1
            ins.append(f"{n}\t{va:#x}\t{f['bytes'].hex()}\t{run}")
    (out / "instructions.tsv").write_text("\n".join(ins) + "\n")
    targets = {a: n for n, (a, _) in extents.items()}
    calls = ["target\tfunction\tsite\tcaller_fde_start"]
    for target, site, owner in caller_scan(img, targets):
        calls.append(f"{target:#x}\t{targets[target]}\t{site:#x}\t{owner:#x}" if owner is not None
                     else f"{target:#x}\t{targets[target]}\t{site:#x}\t-")
    (out / "callers.tsv").write_text("\n".join(calls) + "\n")
    ctl = []
    for fn, mut in MODEL_MUTANTS:
        _, b, _ = evaluate(img, tables, mut=frozenset([mut]), stop_on_first=True, cases=cases_for(fn, 900))
        ctl.append(("model", f"{fn}:{mut}", int(b > 0)))
    ctl += byte_controls(img, tables, extents)
    ctl += input_controls(img)
    (out / "negative-controls.tsv").write_text("kind\tcontrol\tdetected\n" + "".join("\t".join(map(str, r)) + "\n" for r in ctl))
    consts = static_evidence(img, tables, extents)
    (out / "constants.json").write_text(json.dumps(consts, indent=2, sort_keys=True) + "\n")
    det = sum(r[2] for r in ctl)
    summary = {"binary_sha256": SHA256, "cases": total, "mismatches": bad, "chain_sha256": chain.hexdigest(),
               "executed_instructions": {k: v for k, v in sorted(cov.items())},
               "outcome_classes": len(classes), "negative_controls": {"total": len(ctl), "detected": det}}
    (out / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    (out / "measure.json").write_text(json.dumps({"cases": total, "negative_controls": len(ctl),
                                                  "negative_detected": det}, indent=2, sort_keys=True) + "\n")
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
    bad = summary["mismatches"] or summary["negative_controls"]["detected"] != summary["negative_controls"]["total"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
