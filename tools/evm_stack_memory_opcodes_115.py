#!/usr/bin/env python3
"""Reconstruct and validate the node #115 EVM stack, memory and jump opcode handlers.

Opcode handlers are reached through three RELATIVE tables indexed by the opcode byte: 0x6485ef8 and
0x6486c60 (code at 0x43xxxxx, identical entries) and 0x649eea0 (code at 0x4f0xxxx, 0x50bxxxx and
0x546cxxx).  The tool reads the tables from the ELF file and takes the handlers of POP 0x50,
MLOAD 0x51, MSTORE 0x52, MSTORE8 0x53, JUMP 0x56, JUMPI 0x57, PC 0x58, MSIZE 0x59, JUMPDEST 0x5b,
PUSH0 0x5f, PUSH1..PUSH32 0x60..0x7f, DUP1..DUP16 0x80..0x8f and SWAP1..SWAP16 0x90..0x9f.
Every handler takes (rdi = interpreter, rsi = host) and returns a status byte in al: 0 = continue,
0x24 = a stack value does not fit in 64 bits, 0x2a = bad jump destination, 0x2b = opcode not
enabled by the spec byte (+0x1a9), 0x2c = stack underflow, 0x2d = stack overflow.

Interpreter fields used: +0x10 memory object (borrow count +0x10, buffer pointer +0x20, length
+0x28), +0x18 memory base offset, +0x28 stack base (32-byte words, little-endian limbs), +0x30
stack length, +0x118 program-counter pointer, +0x120 analysis object (jump-destination bitmap
pointer +0x18, code length +0x28, code start +0x38), +0x170 memory words already paid for.
Memory accesses round the touched range up to words and call the expansion body 0x45244c0 when it
exceeds +0x170; this tool stubs that call (success up to 300 words, otherwise a fixed failure
code) because the body itself belongs to the LOG packet.  Panics are recorded by their message
pointer.  The tool evaluates the real machine code with the evaluator of
tools/re11_transient_storage115.py (extended here with bt, por, movmskps and sbb-immediate) and compares
every case with one pure-Python reconstruction.  Negative controls show that wrong
reconstructions, corrupted code bytes and wrong handler addresses are detected.
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
import elf_index  # noqa: E402,F401
import fde_extents  # noqa: E402
import re11_transient_storage115 as base  # noqa: E402

BINARY = base.BINARY
SHA256 = base.SHA256
M64 = base.M64
ToolError = base.ToolError
Boundary = base.Boundary
fail = base.fail

TABLES = (("B1", 0x6485ef8), ("B2", 0x6486c60), ("C", 0x649eea0))
EXPAND_TARGET = 0x45244c0
PANIC_A, PANIC_B = 0x1681da0, 0x1681e40
EXPAND_LIMIT = 300
EXPAND_FAIL = 0x30
STACK_BYTES = 1024 * 32
BUFSZ = 16384

INTERP, HOST, STK, CODE, ANA, BITMAP, MEMOBJ, MEMBUF = (
    0x1000_0000, 0x1100_0000, 0x1200_0000, 0x1300_0000, 0x1400_0000, 0x1500_0000, 0x1600_0000, 0x1700_0000)

OPS = {0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8", 0x56: "JUMP", 0x57: "JUMPI",
       0x58: "PC", 0x59: "MSIZE", 0x5b: "JUMPDEST", 0x5f: "PUSH0"}
for _i in range(1, 33):
    OPS[0x5f + _i] = f"PUSH{_i}"
for _i in range(1, 17):
    OPS[0x7f + _i] = f"DUP{_i}"
    OPS[0x8f + _i] = f"SWAP{_i}"

# environment opcodes: (name, minimum spec byte or None, source object, offset, encoding)
ENV = {0x30: ("ADDRESS", None, "interp", 0x78, "addr"), 0x32: ("ORIGIN", None, "host", 0x1c8, "addr"),
       0x33: ("CALLER", None, "interp", 0x8c, "addr"), 0x34: ("CALLVALUE", None, "interp", 0x58, "raw"),
       0x38: ("CODESIZE", None, "ana", 0x50, "u64"), 0x3d: ("RETURNDATASIZE", 4, "interp", 0x160, "u64"),
       0x41: ("COINBASE", None, "host", 0xa8, "addr"), 0x42: ("TIMESTAMP", None, "host", 0x50, "raw"),
       0x43: ("NUMBER", None, "host", 0x30, "raw"), 0x45: ("GASLIMIT", None, "host", 0x90, "u64"),
       0x46: ("CHAINID", 6, "host", 0x258, "u64"), 0x48: ("BASEFEE", 8, "host", 0x98, "u64"),
       0x4b: ("OP4B", 0xe, "host", 0xa0, "u64"), 0x5a: ("GAS", None, "interp", 0x188, "u64")}
OPS.update({op: row[0] for op, row in ENV.items()})
OPS.update({0x36: "CALLDATASIZE", 0x4a: "OP4A", 0x00: "STOP", 0xfe: "INVALID", 0x4c: "UNASSIGNED4C"})
STATUS_ONLY = {0x00: 1, 0xfe: 0x29, 0x4c: 0x26}

MSG = {"mload_range": 0x648f1e8, "mload_base": 0x64bfc68, "mload_end": 0x64bfc80, "msize": 0x64bfc50,
       "mstore_base": 0x64bfd10, "mstore_end": 0x64bfd28, "pc": 0x6486ac8}
MSG_C = {"pc": 0x64a9d28, "mload_range": 0x64af380}


# ---------------------------------------------------------------- evaluator extensions
_decode = base.decode
_EXTRA = {0x0fa3: 0x0fb6, 0x0feb: 0x0fef, 0x0f50: 0x0fef}  # same modrm shape as the stand-in


def decode(code, va):
    p = 0
    while code[p] in (0x66, 0x2e, 0xf3, 0xf2, 0x64):
        p += 1
    if 0x40 <= code[p] <= 0x4f:
        p += 1
    if code[p] == 0x0f and (0x0f00 | code[p + 1]) in _EXTRA:
        real = 0x0f00 | code[p + 1]
        alt = bytearray(code)
        alt[p + 1] = _EXTRA[real] & 0xff
        form = _decode(bytes(alt), va)
        form["op"] = real
        form["bytes"] = bytes(code[:form["len"]])
        return form
    return _decode(code, va)


base.decode = decode


class Machine(base.Machine):
    def step(self, va):
        f = self.fetch(va)
        op, size = f["op"], f["size"]
        nxt = (va + f["len"]) & M64
        if op in (0x81, 0x83) and f["reg"] & 7 == 3:
            a, b = self.get(f["rm"], size, f, va), f["imm"] & ((1 << size) - 1)
            self.put(f["rm"], size, self.flags_sbb(a, b, size), f, va)
            return nxt
        if op == 0x0fa3:
            a = self.get(f["rm"], size, f, va)
            self.cf = bool((a >> (self.reg(f["reg"], size, f) % size)) & 1)
            return nxt
        if op == 0x0feb:
            rm = f["rm"]
            other = self.xmm[rm[1]] if rm[0] == "r" else self.load(self.ea(rm, f, va), 16)
            self.xmm[f["reg"]] |= other
            return nxt
        if op == 0x0f50:
            bits = sum(((self.xmm[f["rm"][1]] >> (32 * i + 31)) & 1) << i for i in range(4))
            self.set_reg(f["reg"], 32, bits, f)
            return nxt
        return super().step(va)


# ---------------------------------------------------------------- ELF facts
def handler_table(image):
    """opcode -> {table name: handler address}, read from the three RELATIVE tables."""
    out = {}
    for op in OPS:
        out[op] = {name: image.word(base_ + 8 * op) for name, base_ in TABLES}
    return out


def extents(image):
    _, fdes = fde_extents.eh_frame_records(image.data, image.secs)
    return {f["start"]: f["end"] for f in fdes}


def handler_list(image):
    """Distinct handler addresses with the (table, opcode) slots that point at them."""
    table = handler_table(image)
    out = {}
    for op in sorted(table):
        for name, addr in table[op].items():
            out.setdefault(addr, []).append((name, op))
    return out


def static_rows(image):
    ext = extents(image)
    rows = []
    for addr, slots in sorted(handler_list(image).items()):
        end = ext[addr]
        calls = []
        try:
            for va, f in base.sweep(image, addr, end):
                if f["op"] == 0xff and f["reg"] & 7 == 2 and f["rm"][0] == "m" and f["rm"][1] == "rip":
                    slot = (va + f["len"] + f["rm"][4]) & M64
                    calls.append(image.word(slot))
        except ToolError:
            pass
        rows.append((addr, end - addr, slots, calls))
    return rows


# ---------------------------------------------------------------- reconstruction (the model)
class Skip(Exception):
    pass


def words_for(end_bytes):
    return (end_bytes >> 5) + (1 if end_bytes & 31 else 0)


def limbs_ok(word):
    return word >> 64 == 0


def jump_target(c, word):
    """Destination checks shared by JUMP and JUMPI: the valid offset, or None."""
    dest = word & M64 if (word >> 64 == 0 or "jump_ignore_high" in c["mut"]) else M64
    if dest >= c["ana_len"] + (1 if "jump_len_inclusive" in c["mut"] else 0):
        return None
    if "jump_no_bitmap" not in c["mut"] and not (c["bitmap"][dest >> 3] >> (dest & 7)) & 1:
        return None
    return dest


def model(c, mut=frozenset()):
    c = dict(c, mut=mut)
    stk = bytearray(c["stack"])
    mem = bytearray(c["buf"])
    n, op = c["len"], c["op"]
    st = {"pc": c["pc"], "borrow": c["borrow"], "words": c["words"], "events": [], "boundary": None}

    def get(i):
        return int.from_bytes(stk[32 * i:32 * i + 32], "little")

    def put(i, v):
        stk[32 * i:32 * i + 32] = v.to_bytes(32, "little")

    def done(ret, length=None):
        return {"ret": ret, "len": n if length is None else length, "stack": bytes(stk), "pc": st["pc"],
                "mem": bytes(mem), "borrow": st["borrow"], "words": st["words"], "events": st["events"],
                "boundary": st["boundary"], "mlen": c["mlen"]}

    def panic(name):
        st["boundary"] = ("panic", (MSG_C if c["table"] == "C" else MSG).get(name, MSG[name]))
        return done(None)

    def expand(end_bytes):
        """Round to words; call the (stubbed) expansion body when it exceeds the paid words."""
        w = words_for(end_bytes) - (1 if "mload_words_floor" in mut and end_bytes & 31 else 0)
        if w > st["words"] and "expand_skipped" not in mut:
            st["events"].append(("expand", w))
            if w > EXPAND_LIMIT:
                return EXPAND_FAIL
            st["words"] = w
        return 0

    if 0x60 <= op <= 0x7f or op == 0x5f:
        k = op - 0x5f
        if op == 0x5f:
            gate = 0x0b if "push0_gate" in mut else 0x0a
            if c["spec"] < gate:
                return done(0x2b)
        if n > (0x3fe if "push_limit" in mut else 0x3ff):
            return done(0x2d)
        data = c["code"][c["pcoff"]:c["pcoff"] + k]
        if op == 0x5f:
            value = 1 if "push0_nonzero" in mut else 0
        else:
            value = int.from_bytes(data, "little" if "push_little" in mut else "big")
            if "push_pc_stay" not in mut:
                st["pc"] = c["pc"] + k
        put(n, value)
        return done(0, n + 1)
    if 0x80 <= op <= 0x8f:
        k = op - 0x7f
        if k + (1 if "dup_off_by_one" in mut else 0) > n and "dup_underflow_ok" not in mut or n >= 0x400:
            return done(0x2d)
        put(n, get(n - k - (1 if "dup_off_by_one" in mut else 0)))
        return done(0, n + 1)
    if 0x90 <= op <= 0x9f:
        k = op - 0x8f
        if n < k + 1:
            return done(0x2d if "swap_err_2d" in mut else 0x2c)
        a, b = get(n - 1), get(n - 1 - k - (1 if "swap_wrong_index" in mut else 0))
        put(n - 1, b)
        put(n - 1 - k - (1 if "swap_wrong_index" in mut else 0), a)
        return done(0)
    if op == 0x50:
        if n == 0:
            return done(0x2d if "pop_err" in mut else 0x2c)
        return done(0, n - 1)
    if op == 0x5b:
        return done(1 if "jumpdest_one" in mut else 0)
    if op == 0x58:
        start = c["start"]
        if c["pc"] == start:
            return panic("pc")
        if n == 0x400:
            return done(0x2d)
        put(n, (c["pc"] - start - (0 if "pc_off_by_one" in mut else 1)) & M64)
        return done(0, n + 1)
    if op == 0x59:
        size = c["mlen"] - (0 if "msize_no_base" in mut else c["base"])
        if size < 0 and "msize_no_panic" not in mut:
            return panic("msize")
        if n == 0x400:
            return done(0x2d)
        put(n, size & M64)
        return done(0, n + 1)
    if op == 0x56:
        if n == 0:
            return done(0x2c)
        n -= 1
        dest = jump_target(c, get(n))
        if dest is None:
            return done(0x2a)
        st["pc"] = (dest + c["start"]) & M64
        return done(0)
    if op == 0x57:
        if n < 2:
            return done(0x2c)
        target, cond = get(n - 1), get(n - 2)
        n -= 2
        taken = cond != 0
        if "jumpi_inverted" in mut:
            taken = not taken
        if "jumpi_low_limb" in mut:
            taken = cond & M64 != 0
        if not taken:
            return done(0, n + 1 if "jumpi_pop_one" in mut else n)
        dest = jump_target(c, target)
        if dest is None:
            return done(0x2a)
        st["pc"] = (dest + c["start"]) & M64
        return done(0)
    if op in STATUS_ONLY:
        return done(STATUS_ONLY[op])
    if op in ENV or op in (0x36, 0x4a):
        return env_model(c, mut, n, stk, done, put)
    # memory opcodes
    base_off = c["base"]
    if op == 0x51:
        if n == 0:
            return done(0x2c)
        off = get(n - 1)
        if off >> 64 and "mload_no_high" not in mut:
            return done(0x24)
        off &= M64
        r13 = off + 0x20
        code_ = expand(M64 if r13 > M64 else r13)
        if code_:
            return done(code_)
        if off > 0xffffffffffffffdf:
            return panic("mload_range")
        st["borrow"] = (st["borrow"] + 1) & M64
        if off + base_off > M64:
            return panic("mload_base")
        if r13 + base_off > M64:
            return panic("mload_end")
        at = off + (0 if "mload_base_ignored" in mut else base_off)
        if at + 32 > BUFSZ:
            raise Skip
        raw = bytes(mem[at:at + 32])
        put(n - 1, int.from_bytes(raw, "little" if "mload_little" in mut else "big"))
        st["borrow"] = (st["borrow"] - 1) & M64
        return done(0)
    if op in (0x52, 0x53):
        if n < 2:
            return done(0x2c)
        off, val = get(n - 1), get(n - 2)
        n -= 2 if "mstore_len_keep" not in mut else 0
        if off >> 64:
            return done(0x24)
        if op == 0x52:
            end = off + 0x20
            code_ = expand(M64 if end > M64 else end)
        else:
            end = off + (0 if "mstore8_end_off" in mut else 1)
            code_ = expand(M64 if end > M64 else end)
        if code_:
            return done(code_)
        st["borrow"] = 0 if "mstore_borrow_left" in mut else M64
        at = off + base_off
        if at > M64:
            return panic("mstore_base")
        if (at >= M64 - 0x1f) if op == 0x52 else at == M64:
            return panic("mstore_end")
        width = 32 if op == 0x52 else 1
        if at + width > BUFSZ:
            raise Skip
        if op == 0x52:
            mem[at:at + 32] = val.to_bytes(32, "big")
        else:
            mem[at] = (val >> 8 if "mstore8_high" in mut else val) & 0xff
        st["borrow"] = (st["borrow"] + 1) & M64
        return done(0)
    raise ToolError(f"opcode {op:#x} outside the model")


def env_model(c, mut, n, stk, done, put):
    """Opcodes that push one field of the interpreter, host or analysis object."""
    op = c["op"]
    objs = {"interp": c["interp"], "host": c["host"], "ana": c["ana"]}
    if op == 0x36:
        raw = c["interp"]
        if int.from_bytes(raw[0x38:0x40], "little") == 0:
            hi, lo = int.from_bytes(raw[0x48:0x50], "little"), int.from_bytes(raw[0x40:0x48], "little")
            value = hi - lo if hi >= lo else 0
        else:
            value = int.from_bytes(raw[0x48:0x50], "little")
        if n == 0x400:
            return done(0x2d)
        put(n, value)
        return done(0, n + 1)
    if op == 0x4a:
        if c["spec"] < 0x0b:
            return done(0x2b)
        host = c["host"]
        value = 0
        if host[0] & 1:
            value = int.from_bytes(host[0x10:0x20], "little")
        if n == 0x400:
            return done(0x2d)
        put(n, value)
        return done(0, n + 1)
    name, gate, where, off, enc = ENV[op]
    if gate is not None and c["spec"] < gate - (1 if "env_gate_low" in mut else 0):
        return done(0x2b)
    if n == 0x400:
        return done(0x2d)
    raw = objs[where]
    if enc == "u64":
        value = int.from_bytes(raw[off:off + 8], "little")
    elif enc == "raw":
        value = int.from_bytes(raw[off:off + 32], "little")
    else:
        value = int.from_bytes(raw[off:off + 20], "little" if "addr_little" in mut else "big")
    put(n, value)
    return done(0, n + 1)


# ---------------------------------------------------------------- machine harness
def junk_regs(m):
    for r in range(16):
        if r != 4:
            m.regs[r] = 0xc1c1_c1c1_c1c1_c1c1


def run_case(m, image, addr, c, stubs):
    m.reset()
    m.stubs = {}
    junk_regs(m)
    interp = bytearray(c["interp"])
    for off, val in ((0x10, MEMOBJ), (0x18, c["base"]), (0x28, STK), (0x30, c["len"]), (0x118, c["pc"]),
                     (0x120, ANA), (0x170, c["words"])):
        interp[off:off + 8] = struct.pack("<Q", val & M64)
    interp[0x1a8], interp[0x1a9] = 0, c["spec"]
    m.add_region(INTERP, 0x400, bytes(interp))
    stack_buf = m.add_region(STK, STACK_BYTES, c["stack"])
    m.add_region(CODE, 0x200, c["code"])
    m.add_region(ANA, 0x80, _ana_bytes(c))
    m.add_region(HOST, 0x400, c["host"])
    m.add_region(BITMAP, 0x100, c["bitmap"])
    memobj = bytearray(0x40)
    memobj[0x10:0x18] = struct.pack("<Q", c["borrow"])
    memobj[0x20:0x28] = struct.pack("<Q", MEMBUF)
    memobj[0x28:0x30] = struct.pack("<Q", c["mlen"])
    m.add_region(MEMOBJ, 0x40, bytes(memobj))
    mem_buf = m.add_region(MEMBUF, BUFSZ + 64, c["buf"])
    events = []

    def expand_stub(mc):
        words = mc.regs[1]
        events.append(("expand", words))
        if mc.regs[7] != INTERP + 0x170 or mc.regs[6] != INTERP or mc.regs[2] != HOST + 0x250:
            fail("expansion call arguments differ from (interp+0x170, interp, host+0x250)")
        if words > EXPAND_LIMIT:
            mc.regs[0] = EXPAND_FAIL
            return
        mc.store(INTERP + 0x170, 8, words)
        mc.regs[0] = 0

    for target in (EXPAND_TARGET,):
        m.stubs[target] = expand_stub
    m.stubs[PANIC_A] = "panic"
    m.stubs[PANIC_B] = "panic"
    m.regs[7], m.regs[6] = INTERP, HOST
    boundary = None
    try:
        m.run(addr)
        ret = m.regs[0] & 0xff
    except Boundary as b:
        ret, boundary = None, ("panic", b.regs[7])
    out = lambda at, size: m.load(at, size)  # noqa: E731
    interp_now = lambda off: out(INTERP + off, 8)  # noqa: E731
    return {"ret": ret, "len": interp_now(0x30), "stack": bytes(stack_buf), "pc": interp_now(0x118),
            "mem": bytes(mem_buf), "borrow": out(MEMOBJ + 0x10, 8), "words": interp_now(0x170),
            "events": events, "boundary": boundary, "mlen": out(MEMOBJ + 0x28, 8)}


def _ana_bytes(c):
    buf = bytearray(c["ana"])
    buf[0x18:0x20] = struct.pack("<Q", BITMAP)
    buf[0x28:0x30] = struct.pack("<Q", c["ana_len"])
    buf[0x38:0x40] = struct.pack("<Q", c["start"])
    return bytes(buf)


# ---------------------------------------------------------------- case generation
def pick(rng, seq):
    return seq[rng.randrange(len(seq))]


def rand_len(rng, lo=0, hi=0x400, specials=()):
    r = rng.randrange(8)
    if r < 3 and specials:
        return pick(rng, specials)
    if r < 5:
        return pick(rng, [lo, hi, hi - 1, lo + 1, hi - 2])
    return rng.randrange(lo, hi + 1)


def base_case(rng, op, addr, table):
    pcoff = rng.randrange(0, 0x80)
    code = bytearray(rng.randbytes(0x200))
    n = 0
    start = pick(rng, [CODE, CODE + pcoff, CODE + pcoff - 1, CODE + pcoff + 5, rng.getrandbits(64), 0])
    c = {"op": op, "addr": addr, "table": table, "stack": rng.randbytes(STACK_BYTES), "len": n,
         "pcoff": pcoff, "pc": CODE + pcoff, "code": bytes(code), "spec": pick(rng, [0, 5, 9, 10, 11, 12, 13, 255]),
         "start": start, "ana_len": 0, "bitmap": rng.randbytes(0x100), "borrow": 0, "base": 0, "words": 0,
         "interp": rng.randbytes(0x400), "host": rng.randbytes(0x400), "ana": rng.randbytes(0x80),
         "mlen": 0, "buf": rng.randbytes(BUFSZ) + bytes(64)}
    return c


def mem_state(rng, c):
    c["base"] = pick(rng, [0, 0, 0, 32, 96, 1000, 1024, M64 - 31, M64 - 5, M64, rng.getrandbits(64)])
    c["words"] = pick(rng, [0, 1, 2, 5, 17, 40, 100, 300, 301, 5000, 1 << 59, (1 << 59) + 1, M64])
    c["mlen"] = pick(rng, [0, 32, 64, 4096, 5000, c["base"], (c["base"] + 32) & M64, max(c["base"] - 1, 0), rng.getrandbits(64)])
    c["borrow"] = pick(rng, [0, 0, 0, 1, 3, M64])


def mem_offset(rng, c, width):
    w = c["words"]
    r = rng.randrange(14)
    if r == 0:
        return rng.getrandbits(64)
    if r == 1:
        return pick(rng, [M64, M64 - 0x1f, M64 - 0x20, M64 - 0x21, M64 - 0x22, M64 - 0x3f, 1 << 63])
    if r == 2:
        return pick(rng, [1, 2, 3]) << 64 | rng.getrandbits(8)
    if r == 3:
        return rng.getrandbits(256)
    if r in (4, 5):
        return rng.randrange(0, min(w, 100) * 32 + 1)
    if r in (6, 7):
        return max(0, min(w, 400) * 32 - width + pick(rng, [-33, -32, -31, -1, 0, 1, 31, 32, 33]))
    if r in (8, 9):
        return rng.randrange(0, 300 * 32)
    return rng.randrange(0, 16)


def stack_set(c, items):
    """Write the listed words (index -> value) into the case stack."""
    buf = bytearray(c["stack"])
    for i, v in items.items():
        buf[32 * i:32 * i + 32] = v.to_bytes(32, "little")
    c["stack"] = bytes(buf)


def make_case(rng, op, addr, table):
    c = base_case(rng, op, addr, table)
    if op in (0x50,):
        c["len"] = rand_len(rng, specials=(0, 1, 2))
    elif op == 0x5b:
        c["len"] = rand_len(rng)
    elif op == 0x5f or 0x60 <= op <= 0x7f:
        c["len"] = rand_len(rng, hi=0x400, specials=(0x3ff, 0x400, 0))
        if op != 0x5f and rng.randrange(4) == 0:
            c["len"] = pick(rng, [0x401, M64])  # PUSH1..32 test "above 0x3ff", not equality
    elif 0x80 <= op <= 0x8f:
        k = op - 0x7f
        c["len"] = pick(rng, [0, k - 1, k, k + 1, 0x3ff, 0x400, 0x401, M64]) if rng.randrange(2) else rng.randrange(0, 0x401)
    elif 0x90 <= op <= 0x9f:
        k = op - 0x8f
        c["len"] = pick(rng, [0, k, k + 1, k + 2, 0x3ff, 0x400]) if rng.randrange(2) else rng.randrange(0, 0x401)
    elif op == 0x58:
        c["len"] = rand_len(rng, specials=(0x3ff, 0x400, 0))
        if rng.randrange(4) == 0:
            c["start"] = c["pc"]
    elif op == 0x59:
        c["len"] = rand_len(rng, specials=(0x3ff, 0x400, 0))
        mem_state(rng, c)
    elif op in (0x56, 0x57):
        c["len"] = pick(rng, [0, 1, 2, 3, 4]) if rng.randrange(2) else rng.randrange(0, 0x401)
        c["ana_len"] = pick(rng, [0, 1, 8, 9, 100, 255, 256, 1000, 2048])
        c["bitmap"] = bytes(pick(rng, [0xff, 0x00, 0x55, 0xaa, rng.randrange(256), rng.randrange(256)]) for _ in range(0x100))
        n = c["len"]
        if n >= 1 and n <= 0x400:
            r = rng.randrange(8)
            if r < 3:
                valid = [d for d in range(0, c["ana_len"]) if (c["bitmap"][d >> 3] >> (d & 7)) & 1]
                dest = pick(rng, valid) if valid else 0
            elif r == 3:
                dest = c["ana_len"] + pick(rng, [0, 1])
            elif r == 4:
                dest = M64
            elif r == 5:
                dest = rng.getrandbits(64)
            else:
                dest = rng.randrange(0, 2100)
            word = dest
            if rng.randrange(6) == 0:
                word |= (pick(rng, [1, 2, 1 << 64, 1 << 127]) << 64)
            items = {n - 1: word}
            if op == 0x57 and n >= 2:
                cond = pick(rng, [0, 0, 1, 1 << 32, 1 << 64, 1 << 128, 1 << 255, rng.getrandbits(256), 1 << 31])
                items[n - 2] = cond
            stack_set(c, items)
    elif op in ENV or op in (0x36, 0x4a, 0x00, 0xfe, 0x4c):
        c["len"] = rand_len(rng, specials=(0x3ff, 0x400, 0))
        if op in (0x36, 0x4a):
            raw = bytearray(c["interp"])
            raw[0x38:0x40] = pick(rng, [bytes(8), bytes(8), b"\x01" + bytes(7)])
            c["interp"] = bytes(raw)
            if rng.randrange(2):
                c["interp"] = c["interp"][:0x40] + pick(rng, [bytes(8), (5).to_bytes(8, "little"), M64.to_bytes(8, "little")]) + c["interp"][0x48:]
            if rng.randrange(2):
                c["interp"] = c["interp"][:0x48] + pick(rng, [bytes(8), (9).to_bytes(8, "little"), (3).to_bytes(8, "little")]) + c["interp"][0x50:]
        if op == 0x4a:
            host = bytearray(c["host"])
            host[0] = pick(rng, [0, 1, 2, 3])
            c["host"] = bytes(host)
    elif op in (0x51, 0x52, 0x53):
        mem_state(rng, c)
        c["len"] = pick(rng, [0, 1, 2, 3, 4]) if rng.randrange(3) == 0 else rng.randrange(0, 0x401)
        n = c["len"]
        if n >= 1:
            width = 1 if op == 0x53 else 32
            items = {n - 1: mem_offset(rng, c, width)}
            if op != 0x51 and n >= 2:
                items[n - 2] = pick(rng, [0, 1, 0xff, 0x100, rng.getrandbits(256), M64, (1 << 256) - 1, 0x1234])
            stack_set(c, items)
    return c


def gen_cases(rng, op, addr, table, count):
    """Generate count valid cases (the model must be able to reach the access, else retry)."""
    made, tries = [], 0
    while len(made) < count and tries < count * 40:
        tries += 1
        c = make_case(rng, op, addr, table)
        try:
            model(c)
        except Skip:
            continue
        made.append(c)
    if len(made) < count:
        fail(f"could not generate {count} cases for opcode {op:#x}")
    return made


COUNTS = {"mem": 250, "jump": 180, "push": 50, "other": 50}


def count_for(op):
    if op in (0x51, 0x52, 0x53):
        return COUNTS["mem"]
    if op in (0x56, 0x57):
        return COUNTS["jump"]
    if op == 0x5f or 0x60 <= op <= 0x7f:
        return COUNTS["push"]
    return COUNTS["other"]


def digest(res):
    h = hashlib.sha256()
    h.update(repr((res["ret"], res["len"], res["pc"], res["borrow"], res["words"], res["events"],
                   res["boundary"], res["mlen"])).encode())
    h.update(res["stack"])
    h.update(res["mem"])
    return h.hexdigest()[:16]


def result_text(res):
    if res["boundary"] is not None:
        return f"panic:{res['boundary'][1]:#x}"
    return f"{res['ret']:#04x}"


def cases_of(addr, op, table, tag="main", scale=1.0):
    rng = random.Random(f"{tag}:{addr:x}:{op:x}")
    return gen_cases(rng, op, addr, table, max(1, int(count_for(op) * scale)))


def trial(m, image, run_addr, c, mut):
    """True when the machine result equals the model; a failing evaluation counts as a mismatch."""
    try:
        return model(c, mut) == run_case(m, image, run_addr, c, None)
    except (ToolError, Skip, IndexError, KeyError, ValueError, AssertionError, OverflowError, struct.error):
        return False


def sweep_handler(m, image, addr, op, table, mut=frozenset(), run_addr=None, override=None, scale=1.0):
    """Cases run until the first mismatch: (cases run, detected)."""
    m.override = override or {}
    m.cache = {}
    n = 0
    for c in cases_of(addr, op, table, scale=scale):
        n += 1
        if not trial(m, image, addr if run_addr is None else run_addr, c, mut):
            return n, True
    return n, False


MUTANTS = (("push_limit", 0x60), ("push_little", 0x61), ("push_pc_stay", 0x60), ("push0_gate", 0x5f),
           ("push0_nonzero", 0x5f), ("dup_off_by_one", 0x81), ("dup_underflow_ok", 0x84), ("swap_err_2d", 0x90),
           ("swap_wrong_index", 0x93), ("pop_err", 0x50), ("jumpdest_one", 0x5b), ("pc_off_by_one", 0x58),
           ("msize_no_base", 0x59), ("msize_no_panic", 0x59), ("jump_ignore_high", 0x56),
           ("jump_len_inclusive", 0x56), ("jump_no_bitmap", 0x56), ("jumpi_inverted", 0x57),
           ("jumpi_low_limb", 0x57), ("jumpi_pop_one", 0x57), ("mload_words_floor", 0x51), ("mload_no_high", 0x51),
           ("mload_little", 0x51), ("mload_base_ignored", 0x51), ("expand_skipped", 0x52),
           ("mstore_len_keep", 0x52), ("mstore_borrow_left", 0x52), ("mstore8_end_off", 0x53),
           ("mstore8_high", 0x53), ("env_gate_low", 0x46), ("addr_little", 0x30))
CORRUPT_OPS = (0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x58, 0x59, 0x5f, 0x60, 0x61, 0x7f, 0x80, 0x81, 0x8f, 0x90,
               0x91, 0x9f, 0x30, 0x34, 0x46, 0x4a, 0x36, 0x5a, 0x38, 0x33, 0x42, 0x45)
SWAPS = ((0x60, 0x61), (0x80, 0x81), (0x90, 0x91), (0x51, 0x52), (0x50, 0x5b), (0x56, 0x57), (0x30, 0x33),
         (0x42, 0x43), (0x45, 0x48), (0x5a, 0x45))


def handler_of(rows, op, table_pref):
    for addr, size, slots, calls in rows:
        for table, o in slots:
            if o == op and table in table_pref:
                return addr, size, table
    fail(f"no handler for opcode {op:#x}")


def run_controls(image, m, rows):
    out = []
    for name, op in MUTANTS:
        for fam, pref in (("B", ("B1", "B2")), ("C", ("C",))):
            addr, _, table = handler_of(rows, op, pref)
            n, det = sweep_handler(m, image, addr, op, table, mut=frozenset([name]))
            out.append((f"mutant:{name}", fam, op, addr, n, "detected" if det else "missed"))
    for i, op in enumerate(CORRUPT_OPS):
        pref = ("B1", "B2") if i % 2 == 0 else ("C",)
        addr, size, table = handler_of(rows, op, pref)
        insns = base.sweep(image, addr, addr + size)
        va, f = insns[2]
        where = va + f["len"] - 1
        old = image.code(where, 1)[0]
        n, det = sweep_handler(m, image, addr, op, table, override={where: old ^ 1})
        status = "detected" if det else ("equivalent" if 0x50 <= f["op"] <= 0x57 else "missed")
        out.append((f"code-byte:{where:#x}", "B" if i % 2 == 0 else "C", op, addr, n, status))
    for a, b in SWAPS:
        addr_a, _, table = handler_of(rows, a, ("B1",))
        addr_b, _, _ = handler_of(rows, b, ("B1",))
        n, det = sweep_handler(m, image, addr_a, a, table, run_addr=addr_b)
        out.append((f"wrong-handler:{b:#x}", "B", a, addr_b, n, "detected" if det else "missed"))
    bad = bytearray(image.data)
    bad[len(bad) // 2] ^= 1
    try:
        base.Image(bytes(bad))
        det = False
    except ToolError:
        det = True
    out.append(("corrupt-binary-sha256", "-", 0, 0, 1, "detected" if det else "missed"))
    addr, _, table = handler_of(rows, 0x60, ("B1",))
    c = dict(cases_of(addr, 0x60, table, scale=0.02)[0], op=0xf0)
    try:
        model(c)
        det = False
    except ToolError:
        det = True
    out.append(("model-unknown-opcode", "-", 0xf0, 0, 1, "detected" if det else "missed"))
    return out


def generate(out):
    out = pathlib.Path(out)
    out.mkdir(parents=True, exist_ok=True)
    image = base.Image(BINARY.read_bytes())
    m = Machine(image)
    rows = static_rows(image)
    total = bad = 0
    with open(out / "cases.tsv", "w", newline="\n") as fh:
        fh.write("handler\ttables\topcode\tname\tindex\tstack_len\tresult\tlen_after\tdigest\n")
        for addr, size, slots, calls in rows:
            op = slots[0][1]
            tables = "+".join(sorted({t for t, _ in slots}))
            m.override, m.cache = {}, {}
            for i, c in enumerate(cases_of(addr, op, slots[0][0])):
                got = run_case(m, image, addr, c, None)
                total += 1
                if model(c) != got:
                    bad += 1
                fh.write(f"{addr:#x}\t{tables}\t{op:#04x}\t{OPS[op]}\t{i}\t{c['len']:#x}\t{result_text(got)}\t"
                         f"{got['len']:#x}\t{digest(got)}\n")
    if bad:
        fail(f"{bad} of {total} cases differ from the reconstruction")
    with open(out / "handlers.tsv", "w", newline="\n") as fh:
        fh.write("handler\tsize\tcode_sha256_16\ttables_and_opcodes\tname\tindirect_call_targets\n")
        for addr, size, slots, calls in rows:
            tag = ",".join(f"{t}:{o:#04x}" for t, o in slots)
            sha = hashlib.sha256(image.code(addr, size)).hexdigest()[:16]
            targets = ",".join(f"{c:#x}" for c in sorted(set(calls)))
            fh.write(f"{addr:#x}\t{size}\t{sha}\t{tag}\t{OPS[slots[0][1]]}\t{targets}\n")
    table = handler_table(image)
    with open(out / "slots.tsv", "w", newline="\n") as fh:
        fh.write("opcode\tname\tB1_0x6485ef8\tB2_0x6486c60\tC_0x649eea0\n")
        for op in sorted(table):
            fh.write(f"{op:#04x}\t{OPS[op]}\t" + "\t".join(f"{table[op][n]:#x}" for n, _ in TABLES) + "\n")
    ctl = run_controls(image, m, rows)
    detected = sum(1 for r in ctl if r[5] == "detected")
    equivalent = [r for r in ctl if r[5] == "equivalent"]
    if detected + len(equivalent) != len(ctl):
        fail("a negative control was neither detected nor an equivalent mutant")
    with open(out / "controls.tsv", "w", newline="\n") as fh:
        fh.write("control\tfamily\topcode\thandler\tcases_run\tdetected\n")
        for name, fam, op, addr, n, det in ctl:
            fh.write(f"{name}\t{fam}\t{op:#04x}\t{addr:#x}\t{n}\t{det}\n")
    if equivalent:
        with open(out / "equivalent-mutants.tsv", "w", newline="\n") as fh:
            fh.write("mutant\thandler\treason\n")
            for name, fam, op, addr, n, det in equivalent:
                fh.write(f"{name}\t{addr:#x}\tpush of a callee-saved register: every register holds the same filler value "
                         f"in the harness and the matching pop restores it, so the register number is unobservable\n")
    measure = {"cases": total, "negative_controls": len(ctl), "negative_detected": detected, "equivalent": len(equivalent),
               "mismatches": bad, "handlers": len(rows)}
    (out / "measure.json").write_text(json.dumps(measure, indent=1, sort_keys=True) + "\n")
    return measure


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    print(json.dumps(generate(args.out), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
