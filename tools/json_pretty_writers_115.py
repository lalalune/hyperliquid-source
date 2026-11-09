"""Reconstruct the pretty-JSON writer family of node #115 and prove it against the bytes.

Five functions of the state/snapshot JSON path are rebuilt as pure Python and compared, case by
case, with the original machine code run on the shared concrete evaluator of
`decimal_scaled_u64`: the string escaper 0x25bf330, the byte-slice array writer 0x25bf560, the
object key writer 0x26077c0, the object closer 0x26079d0 and the struct opener 0x22ebc70.
The binary is never executed; every number below comes from reading ELF bytes.
"""
import argparse
import hashlib
import json
import pathlib
import random
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import decimal_scaled_u64 as core  # noqa: E402
from decimal_scaled_u64 import Done, Image, Machine, ToolError  # noqa: E402

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BINARY = HERE.parent / "artifacts" / "node" / "115" / "hl-node"

F_ESC, F_SEQ, F_KEY, F_END, F_BEGIN = 0x25bf330, 0x25bf560, 0x26077c0, 0x26079d0, 0x22ebc70
F_GROW, F_CLOSE, F_VALUE = 0x231e050, 0x232b070, 0x2c6c800
SLOT_ESC, SLOT_HEX, SLOT_COPY, SLOT_PANIC_A, SLOT_PANIC_B = 0x64e13d8, 0x64e13e0, 0x64df508, 0x64df520, 0x64df730
SLOT_PANIC_C = 0x64df848
COPY_SYMBOL_INDEX = 7  # the .rela.dyn GLOB_DAT entry of the copy slot names dynamic symbol 7
COPY_SENTINEL = 0x5eed_0000
DEC_LUT = 0x5f1383
KEY_TEXT, KEY_LEN = 0x458fc8, 8
FUNCTIONS = (("escape_contents", F_ESC), ("byte_array", F_SEQ), ("object_key", F_KEY),
             ("object_end", F_END), ("struct_open", F_BEGIN), ("object_close", F_CLOSE))

WRITER, BUF, KEYMEM, INDMEM, SER, STATE, ELEM, HOLDER = (0x7200_0000, 0x7300_0000, 0x7400_0000, 0x7500_0000,
                                                        0x7600_0000, 0x7610_0000, 0x7700_0000, 0x7800_0000)
STACK_TOP = core.STACK + 0x800
U64 = core.U64
GROUPS = ("escape", "array", "key", "end", "close", "begin")
PER_GROUP = {"escape": 3600, "array": 2600, "key": 2200, "end": 400, "close": 1400, "begin": 1800}
SAMPLE_ROWS = 100
PANEL = 24


# ---------------------------------------------------------------- reference model (pure Python)

CANON_ESCAPE = bytes([{8: 0x62, 9: 0x74, 10: 0x6e, 12: 0x66, 13: 0x72, 0x22: 0x22, 0x5c: 0x5c}.get(
    i, 0x75 if i < 0x20 else 0) for i in range(256)])


class Variant:
    """Knobs that let the negative controls build deliberately wrong reference models."""

    def __init__(self, **kw):
        self.kw = kw

    def get(self, name, default):
        return self.kw.get(name, default)


NORMAL = Variant()


def ref_escape(data, esc, hexes, var=NORMAL):
    out = bytearray()
    for b in data:
        e = esc[b]
        if var.get("skip_escape", False):
            e = 0
        if e == 0:
            out.append(b)
        elif e == 0x75:
            out += b"\\u" + var.get("zeros", b"00") + bytes([hexes[b >> 4], hexes[b & 15]])
        else:
            out += b"\\" + bytes([e])
    return bytes(out)


def ref_indent(indent, count, var):
    return indent * (count + var.get("indent_extra", 0)) if count + var.get("indent_extra", 0) > 0 else b""


def ref_key(err, state, indent, depth, key, esc, hexes, var=NORMAL):
    if err == 1:
        return None
    first, nxt = var.get("first", b"\n"), var.get("next", b",\n")
    out = (first if state == 1 else nxt) + ref_indent(indent, depth, var)
    out += var.get("open_quote", b'"') + ref_escape(key, esc, hexes, var) + var.get("close_quote", b'"')
    return out, 2


def ref_end(err, state, var=NORMAL):
    if err == 1:
        return None
    return b"" if state == 0 else var.get("brace", b"}")


def ref_digits(n, lut, var):
    text = b""
    if n >= 100:
        text = bytes([0x30 | n // 100]) + lut[2 * (n % 100):2 * (n % 100) + 2]
    elif n >= 10:
        text = lut[2 * n:2 * n + 2]
    else:
        text = bytes([0x30 | n])
    if var.get("pad", False):
        text = text.rjust(3, b"0")
    return text


def ref_array(indent, cur, data, lut, var=NORMAL):
    """Returns (output, new_current_indent, has_value) or None when the depth counter overflows."""
    if cur == U64:
        return None
    out = bytearray(var.get("open", b"["))
    if not data:
        return bytes(out) + b"]", cur, 0
    for i, b in enumerate(data):
        out += (var.get("first", b"\n") if i == 0 else var.get("next", b",\n"))
        out += ref_indent(indent, cur + 1, var)
        out += ref_digits(b, lut, var)
    out += b"\n" + ref_indent(indent, cur, var) + var.get("close", b"]")
    return bytes(out), cur, 1


def ref_close(indent, cur, has, var=NORMAL):
    """Returns (output, new_current_indent) or None when the depth counter is already zero."""
    if cur == 0:
        return None
    cur -= 1
    out = b""
    if has:
        out = var.get("newline", b"\n") + ref_indent(indent, cur, var)
    return out + var.get("brace", b"}"), cur


def ref_begin(indent, depth, value_fails, key, esc, hexes, var=NORMAL):
    """Returns (output, depth_after, has_value_after) or None on overflow of the depth counter."""
    if depth == U64:
        return None
    depth += 1
    out = bytearray(var.get("open", b"{"))
    out += ref_key(0, 1, indent, depth, key, esc, hexes, var)[0]
    out += var.get("colon", b": ")
    out += b"<V>"
    if value_fails:
        return bytes(out), depth, 0
    closed = ref_close(indent, depth, 1, var)
    return bytes(out) + closed[0], closed[1], 1


# ---------------------------------------------------------------- evaluator harness

class Emu(Machine):
    """Concrete evaluator with the buffer-growth, copy and callee hooks the writers need."""

    def __init__(self, image, hooks):
        super().__init__(image)
        self.hooks = hooks
        self.log = []
        self.grows = 0
        self.spurious_grow = False
        for r in range(16):
            self.set_reg(r, 0)
        self.set_reg(core.RSP, STACK_TOP)
        self.store(STACK_TOP, 8, core.RETURN_MARK)
        for slot in (SLOT_ESC, SLOT_HEX):
            self.store(slot, 8, image.slots[slot])
        self.store(SLOT_COPY, 8, COPY_SENTINEL)

    def step(self):
        insn = self.image.fetch(self.pc)
        if insn.key == 0xff and (self.image.data[insn.modrm] >> 3) & 7 == 2:
            operand = self.operand(insn)
            if operand[0] == "r":
                target = self.get(operand[1], 64)
                if target is None:
                    core.fail(f"indirect call through unknown register at {self.pc:#x}")
                here = self.pc
                self.pc = here + insn.size
                self.call(target, here)
                return
        super().step()

    def clobber(self, rax):
        for reg in core.CALLER_SAVED:
            self.put(reg, 64, None)
        self.set_reg(core.RAX, rax)
        self.flags = [None, None, None, None]

    def push_marker(self, writer, text):
        cap, ptr, length = (self.load(writer + 8 * i, 8) for i in range(3))
        if cap - length < len(text):
            self.store(writer, 8, length + len(text))
        for i, b in enumerate(text):
            self.store(ptr + length + i, 1, b)
        self.store(writer + 16, 8, length + len(text))

    def call(self, target, where):
        img = self.image
        if target == COPY_SENTINEL:
            dst, src, n = (self.get(r, 64) for r in (core.RDI, core.RSI, core.RDX))
            data = []
            for i in range(n):
                b = self.mem.get(src + i)
                if b is None:
                    b = img.read_only(src + i)
                if b is None:
                    core.fail(f"copy from unmapped byte {src + i:#x}")
                data.append(b)
            for i, b in enumerate(data):
                self.mem[dst + i] = b
            self.clobber(dst)
        elif target == F_GROW:
            vec, length, add = (self.get(r, 64) for r in (core.RDI, core.RSI, core.RDX))
            cap = self.load(vec, 8)
            self.grows += 1
            if cap - length >= add:
                self.spurious_grow = True
            self.store(vec, 8, length + add)
            self.clobber(0)
        elif target == F_VALUE:
            first, ser = self.get(core.RDI, 64), self.get(core.RSI, 64)
            self.log.append(("value", first, ser))
            self.push_marker(self.load(ser, 8), b"<V>")
            self.clobber(self.hooks["value_result"])
        else:
            super().call(target, where)


def new_image():
    data = bytearray(BINARY.read_bytes())
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise ToolError("binary digest differs from node #115")
    img = Image(data)
    img.panic_targets = {img.slots[s] for s in (SLOT_PANIC_A, SLOT_PANIC_B, SLOT_PANIC_C)}
    img.slots[SLOT_COPY] = COPY_SENTINEL  # a dynamic-symbol slot: no relative target exists
    return img


def read_va(img, va, n):
    off = img.file_offset(va)
    return bytes(img.data[off:off + n])


def put_bytes(m, at, data):
    for i, b in enumerate(data):
        m.store(at + i, 1, b)


def put_writer(m, prefix, cap):
    m.store(WRITER, 8, cap)
    m.store(WRITER + 8, 8, BUF)
    m.store(WRITER + 16, 8, len(prefix))
    put_bytes(m, BUF, prefix)


def take_writer(m):
    cap, ptr, length = (m.load(WRITER + 8 * i, 8) for i in range(3))
    out = bytes(m.mem.get(ptr + i, 0xee) for i in range(length))
    top = max([a - BUF for a in m.mem if BUF <= a < BUF + 0x100000] or [-1])
    return out, cap, length, top


def execute(m, start, regs):
    for reg, value in regs.items():
        m.set_reg(reg, value)
    try:
        m.run(start)
    except Done as done:
        return done.how
    raise ToolError("run ended without a stop")


def check_writer(m, how, length_before):
    out, cap, length, top = take_writer(m)
    if how != "ret":
        return out
    if length > cap or top >= length:
        raise ToolError("writer invariant broken: bytes beyond the length or length beyond capacity")
    if m.spurious_grow:
        raise ToolError("growth requested although room remained")
    return out


# ---------------------------------------------------------------- case drivers

def run_escape(img, tab, case):
    prefix, data, cap = case
    m = Emu(img, {})
    put_writer(m, prefix, cap)
    put_bytes(m, KEYMEM, data)
    how = execute(m, F_ESC, {core.RDI: WRITER, core.RSI: KEYMEM, core.RDX: len(data)})
    return how, check_writer(m, how, len(prefix)), m.grows


def expect_escape(tab, case, var=NORMAL):
    prefix, data, cap = case
    return "ret", prefix + ref_escape(data, tab["esc"], tab["hex"], var)


def run_array(img, tab, case):
    prefix, indent, cur, data, cap = case
    m = Emu(img, {})
    put_writer(m, prefix, cap)
    put_bytes(m, INDMEM, indent)
    put_bytes(m, ELEM, data)
    m.store(HOLDER, 8, WRITER)
    for off, val in ((0, INDMEM), (8, len(indent)), (16, cur), (24, 0xff)):
        m.store(SER + off, 8, val)
    how = execute(m, F_SEQ, {core.RDI: SER, core.RSI: HOLDER, core.RDX: ELEM, core.RCX: len(data)})
    out = check_writer(m, how, len(prefix))
    return how, out, (m.load(SER + 16, 8), m.load(SER + 24, 1)), m.grows


def expect_array(tab, case, var=NORMAL):
    prefix, indent, cur, data, cap = case
    ref = ref_array(indent, cur, data, tab["lut"], var)
    if ref is None:
        return "panic", None, None
    return "ret", prefix + ref[0], (ref[1], ref[2])


def run_key(img, tab, case):
    prefix, err, state, indent, depth, key, cap = case
    m = Emu(img, {})
    put_writer(m, prefix, cap)
    put_bytes(m, INDMEM, indent)
    put_bytes(m, KEYMEM, key)
    for off, val in ((0, WRITER), (8, INDMEM), (16, len(indent)), (24, depth)):
        m.store(SER + off, 8, val)
    m.store(STATE, 1, err)
    m.store(STATE + 1, 1, state)
    m.store(STATE + 8, 8, SER)
    how = execute(m, F_KEY, {core.RDI: STATE, core.RSI: KEYMEM, core.RDX: len(key)})
    return how, check_writer(m, how, len(prefix)), m.load(STATE + 1, 1), m.grows


def expect_key(tab, case, var=NORMAL):
    prefix, err, state, indent, depth, key, cap = case
    ref = ref_key(err, state, indent, depth, key, tab["esc"], tab["hex"], var)
    if ref is None:
        return "panic", None, None
    return "ret", prefix + ref[0], ref[1]


def run_end(img, tab, case):
    prefix, err, state, cap = case
    m = Emu(img, {})
    put_writer(m, prefix, cap)
    m.store(STATE, 1, err)
    m.store(STATE + 1, 1, state)
    m.store(STATE + 8, 8, HOLDER)
    m.store(HOLDER, 8, WRITER)
    how = execute(m, F_END, {core.RDI: STATE})
    return how, check_writer(m, how, len(prefix)), m.grows


def expect_end(tab, case, var=NORMAL):
    prefix, err, state, cap = case
    ref = ref_end(err, state, var)
    if ref is None:
        return "panic", None
    return "ret", prefix + ref


def run_close(img, tab, case):
    prefix, indent, cur, has, cap = case
    m = Emu(img, {})
    put_writer(m, prefix, cap)
    put_bytes(m, INDMEM, indent)
    for off, val in ((0, INDMEM), (8, len(indent)), (16, cur), (24, has)):
        m.store(SER + off, 8, val)
    how = execute(m, F_CLOSE, {core.RDI: SER, core.RSI: WRITER})
    return how, check_writer(m, how, len(prefix)), (m.load(SER + 16, 8), m.load(SER + 24, 1)), m.grows


def expect_close(tab, case, var=NORMAL):
    prefix, indent, cur, has, cap = case
    ref = ref_close(indent, cur, has, var)
    if ref is None:
        return "panic", None, None
    return "ret", prefix + ref[0], (ref[1], has)


def run_begin(img, tab, case):
    prefix, indent, depth, fails, cap = case
    m = Emu(img, {"value_result": 0x1234 if fails else 0})
    put_writer(m, prefix, cap)
    put_bytes(m, INDMEM, indent)
    m.store(HOLDER, 8, 0xabcdef)
    for off, val in ((0, WRITER), (8, INDMEM), (16, len(indent)), (24, depth), (32, 0x55)):
        m.store(SER + off, 8, val)
    how = execute(m, F_BEGIN, {core.RDI: HOLDER, core.RSI: SER})
    out = check_writer(m, how, len(prefix))
    wiring = tuple(entry[1] == 0xabcdef and entry[2] == SER for entry in m.log)
    rax = m.get(core.RAX, 64) if how == "ret" else None
    return how, out, (m.load(SER + 24, 8), m.load(SER + 32, 1)), wiring, rax, m.grows


def expect_begin(tab, case, key, var=NORMAL):
    prefix, indent, depth, fails, cap = case
    ref = ref_begin(indent, depth, fails, key, tab["esc"], tab["hex"], var)
    if ref is None:
        return "panic", None, None, None, None
    return "ret", prefix + ref[0], (ref[1], ref[2]), (True,), 0x1234 if fails else 0


def observe(group, img, tab, case):
    """Run one case; returns the comparable observation without the growth count."""
    runner = {"escape": run_escape, "array": run_array, "key": run_key, "end": run_end, "close": run_close,
              "begin": run_begin}[group]
    got = runner(img, tab, case)
    return got[:-1], got[-1]


def expected(group, tab, case, var=NORMAL):
    if group == "escape":
        return expect_escape(tab, case, var)
    if group == "array":
        return expect_array(tab, case, var)
    if group == "key":
        return expect_key(tab, case, var)
    if group == "end":
        return expect_end(tab, case, var)
    if group == "close":
        return expect_close(tab, case, var)
    return expect_begin(tab, case, tab["key"], var)


def comparable(group, got):
    """Normalise an observation so a panic compares only by outcome."""
    if got[0] == "panic":
        return ("panic",)
    return got


# ---------------------------------------------------------------- case generators

SPECIAL = [0, 1, 7, 8, 9, 10, 11, 12, 13, 31, 32, 34, 47, 92, 93, 126, 127, 128, 200, 255]
INDENTS = [b"", b" ", b"  ", b"    ", b"\t", b" \t"]
CAPS = [0, 1, 2, 3, 5, 6, 8, 13, 64, 4096]


def rand_bytes(rng, top):
    n = rng.choice([0, 0, 1, 2, 3, 5, 8, 13, 21, 40])
    pool = rng.choice([SPECIAL, list(range(32)), list(range(256)), list(range(32, 127))])
    return bytes(rng.choice(pool) for _ in range(min(n, top)))


def gen_cases(group, count):
    rng = random.Random(f"json-pretty-115-{group}")
    for i in range(count):
        prefix = bytes(rng.choice(b"abc{") for _ in range(rng.choice([0, 0, 1, 4])))
        cap = len(prefix) + rng.choice(CAPS)
        if group == "escape":
            yield (prefix, rand_bytes(rng, 40), cap)
        elif group == "array":
            data = bytes(rng.choice([rng.randrange(256), rng.choice([0, 9, 10, 99, 100, 101, 199, 200, 255])])
                         for _ in range(rng.choice([0, 1, 2, 3, 5, 9, 17])))
            cur = U64 if i % 331 == 330 else rng.choice([0, 0, 1, 2, 3])
            yield (prefix, rng.choice(INDENTS), cur, data, cap)
        elif group == "key":
            yield (prefix, 1 if i % 53 == 52 else 0, rng.choice([0, 1, 2, 2, 7]), rng.choice(INDENTS),
                   rng.choice([0, 0, 1, 2, 3, 5]), rand_bytes(rng, 24), cap)
        elif group == "end":
            yield (prefix, 1 if i % 4 == 3 else 0, rng.choice([0, 1, 2, 5]), cap)
        elif group == "close":
            yield (prefix, rng.choice(INDENTS), 0 if i % 17 == 16 else rng.choice([1, 1, 2, 3, 4]),
                   rng.choice([0, 1]), cap)
        else:
            depth = U64 if i % 211 == 210 else rng.choice([0, 0, 1, 2, 4])
            yield (prefix, rng.choice(INDENTS), depth, rng.random() < 0.3, cap)


def case_text(case):
    return ",".join(x.hex() if isinstance(x, bytes) else str(x) for x in case)


def obs_text(obs):
    return json.dumps(obs, default=lambda v: v.hex() if isinstance(v, bytes) else str(v), sort_keys=True)


# ---------------------------------------------------------------- derived tables

def derive_tables(img):
    esc = read_va(img, img.slots[SLOT_ESC], 256)
    hexes = read_va(img, img.slots[SLOT_HEX], 16)
    lut = read_va(img, DEC_LUT, 200)
    key = read_va(img, KEY_TEXT, KEY_LEN)
    return {"esc": esc, "hex": hexes, "lut": lut, "key": key}


def table_rows(img, tab):
    rows = [("escape_table", i, f"{tab['esc'][i]:#04x}", f"{CANON_ESCAPE[i]:#04x}", str(tab["esc"][i] == CANON_ESCAPE[i]))
            for i in range(256)]
    rows += [("hex_digit", i, f"{tab['hex'][i]:#04x}", f"{b'0123456789abcdef'[i]:#04x}",
              str(tab["hex"][i] == b"0123456789abcdef"[i])) for i in range(16)]
    lut_ref = b"".join(b"%02d" % i for i in range(100))
    rows += [("decimal_pair", i, tab["lut"][2 * i:2 * i + 2].decode(), "%02d" % i,
              str(tab["lut"][2 * i:2 * i + 2] == lut_ref[2 * i:2 * i + 2])) for i in range(100)]
    rows.append(("copy_slot_symbol", COPY_SYMBOL_INDEX, copy_symbol_name(img), "memcpy",
                 str(copy_symbol_name(img) == "memcpy")))
    rows.append(("object_key_text", 0, tab["key"].decode(), "exchange", str(tab["key"] == b"exchange")))
    return rows


def copy_symbol_name(img):
    """Name of dynamic symbol 7, read from .dynsym/.dynstr, and the relocation that binds the copy slot."""
    rela_off, rela_size = img.sections[".rela.dyn"][1:]
    found = False
    for addr, info, _ in struct.iter_unpack("<QQq", bytes(img.data[rela_off:rela_off + rela_size])):
        if addr == SLOT_COPY:
            found = info == (COPY_SYMBOL_INDEX << 32 | 6)
    if not found:
        raise ToolError("the copy slot is not a GLOB_DAT relocation of the expected symbol")
    sym_off = img.sections[".dynsym"][1] + 24 * COPY_SYMBOL_INDEX
    name_at = struct.unpack_from("<I", img.data, sym_off)[0]
    str_off = img.sections[".dynstr"][1] + name_at
    return bytes(img.data[str_off:img.data.index(b"\0", str_off)]).decode()


def function_rows(img):
    rows = []
    for name, start in FUNCTIONS:
        lo, hi = img.fde_of(start)
        digest = hashlib.sha256(read_va(img, lo, hi - lo)).hexdigest()
        rows.append((name, f"{start:#x}", f"{lo:#x}", f"{hi:#x}", hi - lo, digest))
    for name, start in (("buffer_reserve", F_GROW), ("value_serializer", F_VALUE)):
        lo, hi = img.fde_of(start)
        rows.append((name + "_hooked", f"{start:#x}", f"{lo:#x}", f"{hi:#x}", hi - lo, "-"))
    return rows


# ---------------------------------------------------------------- negative controls

def patch_detect(img, tab, group, va, delta, panel):
    """Flip one byte (xor delta) of the original code, rerun a panel and report whether it differs."""
    off = img.file_offset(va)
    old = img.data[off]
    img.data[off] = old ^ delta
    img.cache.clear()
    try:
        for case in panel:
            try:
                got, _ = observe(group, img, tab, case)
            except (ToolError, Done, IndexError, KeyError, TypeError):
                return True
            if comparable(group, got) != comparable(group, expected(group, tab, case)):
                return True
        return False
    finally:
        img.data[off] = old
        img.cache.clear()


def variant_detect(group, tab, var, observed):
    for case, got in observed:
        if comparable(group, got) != comparable(group, expected(group, tab, case, var)):
            return True
    return False


def make_controls():
    """(name, group, kind, argument) rows; every one must be detected."""
    patches = [
        ("key opening quote 0x22 -> 0x23", "key", 0x26078e9 + 3, 1),
        ("key closing quote 0x22 -> 0x23", "key", 0x260790c + 3, 1),
        ("key first-entry newline 0x0a -> 0x0b", "key", 0x2607807 + 3, 1),
        ("key comma-newline immediate low byte", "key", 0x260782c + 4, 0x17),
        ("key error-byte branch je -> jne", "key", 0x26077d1 + 0, 1),
        ("key first-state compare 0x01 -> 0x00", "key", 0x26077db + 3, 1),
        ("escape unicode prefix immediate", "escape", 0x25bf40b + 3, 1),
        ("escape unicode selector 0x75 -> 0x76", "escape", 0x25bf3d9 + 3, 3),
        ("escape backslash 0x5c -> 0x5d", "escape", 0x25bf448 + 3, 1),
        ("array opening bracket 0x5b -> 0x5c", "array", 0x25bf5a5 + 3, 7),
        ("array closing bracket 0x5d -> 0x5e", "array", 0x25bf867 + 3, 3),
        ("array first newline 0x0a -> 0x0b", "array", 0x25bf601 + 3, 1),
        ("array comma-newline immediate", "array", 0x25bf684 + 4, 0x17),
        ("array hundred threshold 0x63 -> 0x62", "array", 0x25bf6a7 + 3, 1),
        ("array ten threshold 0x0a -> 0x0b", "array", 0x25bf6e6 + 1, 1),
        ("end brace 0x7d -> 0x7e", "end", 0x26079f0 + 3, 3),
        ("end state test je -> jne", "end", 0x26079da + 0, 1),
        ("close newline 0x0a -> 0x0b", "close", 0x232b0ad + 3, 1),
        ("close brace 0x7d -> 0x7e", "close", 0x232b134 + 3, 3),
        ("close zero-depth test je -> jne", "close", 0x232b082, 1),
        ("close has-value test je -> jne", "close", 0x232b096, 1),
        ("begin opening brace 0x7b -> 0x7c", "begin", 0x22ebca9 + 3, 7),
        ("begin colon immediate 0x203a -> 0x203b", "begin", 0x22ebd00 + 4, 1),
        ("begin value-failure branch jne -> je", "begin", 0x22ebd19, 1),
    ]
    rows = [(name, group, "patch", (va, delta)) for name, group, va, delta in patches]
    rows += [
        ("escape table: newline entry n -> m", "escape", "table", ("esc", 10, 0x6d)),
        ("escape table: quote entry cleared", "escape", "table", ("esc", 0x22, 0)),
        ("escape table: 0x7f escaped as unicode", "escape", "table", ("esc", 0x7f, 0x75)),
        ("hex table: upper-case digits", "escape", "table", ("hex", 10, 0x41)),
        ("decimal pair table: 42 -> 43", "array", "table", ("lut", 84, 0x30)),
    ]
    variants = [
        ("model: key without separator after first entry", "key", {"next": b"\n"}),
        ("model: key with extra indent level", "key", {"indent_extra": 1}),
        ("model: key quotes dropped", "key", {"open_quote": b"", "close_quote": b""}),
        ("model: escaper disabled", "escape", {"skip_escape": True}),
        ("model: unicode escape with three zeros", "escape", {"zeros": b"000"}),
        ("model: end writes bracket", "end", {"brace": b"]"}),
        ("model: array digits zero padded", "array", {"pad": True}),
        ("model: array one indent level short", "array", {"indent_extra": -1}),
        ("model: array closes with brace", "array", {"close": b"}"}),
        ("model: close without newline before brace", "close", {"newline": b""}),
        ("model: close indents one level deeper", "close", {"indent_extra": 1}),
        ("model: close writes opening brace", "close", {"brace": b"{"}),
        ("model: begin colon without space", "begin", {"colon": b":"}),
        ("model: begin opens with bracket", "begin", {"open": b"["}),
    ]
    rows += [(name, group, "variant", Variant(**kw)) for name, group, kw in variants]
    rows += [
        ("input: start address outside every FDE", "any", "outside", 0x1000),
        ("input: start address inside data not code", "any", "rodata", DEC_LUT),
        ("input: binary digest corrupted", "any", "digest", None),
    ]
    return rows


def run_control(img, tab, row, panels, observed):
    name, group, kind, arg = row
    if kind == "patch":
        return patch_detect(img, tab, group, arg[0], arg[1], panels[group])
    if kind == "table":
        table, index, value = arg
        base = {"esc": img.slots[SLOT_ESC], "hex": img.slots[SLOT_HEX], "lut": DEC_LUT}[table]
        return table_detect(img, tab, group, base + index, value, panels[group])
    if kind == "variant":
        return variant_detect(group, tab, arg, observed[group])
    if kind == "outside":
        try:
            img.fde_of(arg)
        except ToolError:
            return True
        return False
    if kind == "rodata":
        try:
            Emu(img, {}).run(arg)
        except ToolError:
            return True
        except Done:
            return False
        return False
    corrupt = bytearray(img.data[:4096])
    corrupt[17] ^= 1
    return hashlib.sha256(corrupt).hexdigest() != DIGEST


def table_detect(img, tab, group, va, value, panel):
    """Overwrite a table byte in the image (the model keeps the true table) and rerun a panel."""
    off = img.file_offset(va)
    old = img.data[off]
    img.data[off] = value
    img.cache.clear()
    try:
        for case in panel:
            try:
                got, _ = observe(group, img, tab, case)
            except (ToolError, Done, IndexError, KeyError, TypeError):
                return True
            if comparable(group, got) != comparable(group, expected(group, tab, case)):
                return True
        return False
    finally:
        img.data[off] = old
        img.cache.clear()


# ---------------------------------------------------------------- driver

ANCHORS = (
    ("escape", (b"", bytes(range(0, 40)) + b'"\\\x7f', 4096)),
    ("array", (b"", b"  ", 1, bytes([0, 5, 9, 10, 42, 99, 100, 150, 255]), 4096)),
    ("key", (b"", 0, 2, b"  ", 2, bytes(range(0, 40)) + b'"\\', 4096)),
)

def build(out_dir):
    img = new_image()
    tab = derive_tables(img)
    for name, start in FUNCTIONS:
        img.fde_of(start)
    stats = {}
    samples = []
    panels = {g: [] for g in GROUPS}
    observed = {g: [] for g in GROUPS}
    total_cases = 0
    for group in GROUPS:
        digest = hashlib.sha256()
        grows = panics = rets = mismatches = 0
        for index, case in enumerate(gen_cases(group, PER_GROUP[group])):
            got, grown = observe(group, img, tab, case)
            want = expected(group, tab, case)
            same = comparable(group, got) == comparable(group, want)
            mismatches += not same
            grows += grown
            panics += got[0] == "panic"
            rets += got[0] == "ret"
            digest.update((case_text(case) + "|" + obs_text(comparable(group, got)) + "\n").encode())
            if len(panels[group]) < PANEL and (index % 7 == 0 or got[0] == "panic"):
                panels[group].append(case)
                observed[group].append((case, comparable(group, got)))
            if index < SAMPLE_ROWS:
                samples.append((group, index, case_text(case), obs_text(comparable(group, got)), str(same)))
        if mismatches:
            raise ToolError(f"{group}: {mismatches} cases differ from the reconstruction")
        stats[group] = (PER_GROUP[group], rets, panics, grows, digest.hexdigest())
        total_cases += PER_GROUP[group]
    for group, case in ANCHORS:
        got, _ = observe(group, img, tab, case)
        panels[group].append(case)
        observed[group].append((case, comparable(group, got)))
    controls = make_controls()
    control_rows = []
    detected = 0
    for row in controls:
        hit = run_control(img, tab, row, panels, observed)
        detected += bool(hit)
        control_rows.append((row[0], row[1], row[2], str(hit)))
    if detected != len(controls):
        missed = [r[0] for r in control_rows if r[3] != "True"]
        raise ToolError(f"controls not detected: {missed}")
    write_outputs(pathlib.Path(out_dir), img, tab, stats, samples, control_rows, total_cases, len(controls), detected)
    return stats


def tsv(path, header, rows):
    with open(path, "w", newline="\n") as fh:
        fh.write("\t".join(header) + "\n")
        for row in rows:
            fh.write("\t".join(str(c) for c in row) + "\n")


def write_outputs(out, img, tab, stats, samples, control_rows, cases, controls, detected):
    out.mkdir(parents=True, exist_ok=True)
    tsv(out / "functions.tsv", ("role", "entry", "fde_start", "fde_end", "length", "sha256"), function_rows(img))
    tsv(out / "tables.tsv", ("table", "index", "bytes_value", "expected_value", "match"), table_rows(img, tab))
    tsv(out / "groups.tsv", ("group", "cases", "returned", "panicked", "growth_calls", "stream_sha256"),
        [(g,) + stats[g] for g in GROUPS])
    tsv(out / "cases.tsv", ("group", "index", "inputs_hex", "observation", "reconstruction_agrees"), samples)
    tsv(out / "controls.tsv", ("control", "group", "kind", "detected"), control_rows)
    (out / "measure.json").write_text(json.dumps(
        {"cases": cases, "negative_controls": controls, "negative_detected": detected,
         "binary_sha256": DIGEST}, indent=1, sort_keys=True) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="evidence folder to (re)generate")
    args = parser.parse_args(argv)
    stats = build(args.out)
    for group in GROUPS:
        print(group, *stats[group])


if __name__ == "__main__":
    main()
