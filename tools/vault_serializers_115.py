#!/usr/bin/env python3
"""Reconstruct the node #115 Vault struct serializers: the tagged writer 0x44a66f0 and the MessagePack writer 0x44a6a20.

Both bodies serialize the 13 element Vault record (name, description, create_time, vault_user, leader, user_states, leader_commission,
is_closed, lockup_duration, allow_deposits, the extra record helper, always_close_on_withdraw, relationship). The real bytes run in the
small x86-64 evaluator of tools/bole_rate115.py with every callee replaced by a recording stub. A separately written rule list predicts
the ordered stub calls (callee, decoded arguments), the 24 byte result record, the growth requests and the bytes written inline into the
output buffer. Corrupted rule lists, corrupted code bytes and out of range inputs must all be refused. No objdump or readelf output is
parsed and the binary is never executed. Standard library only.

    python3 tools/vault_serializers_115.py --out <dir>
"""

import argparse
import hashlib
import json
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bole_rate115 as base  # noqa: E402
from bole_rate115 import (  # noqa: E402
    EvidenceError, Halt, HEAP_BASE, Machine, R8, RCX, RDI, RDX, RSI, STACK_TOP, decode_range, load_image,
)

TAGGED = 0x44A66F0
PACKED = 0x44A6A20
TARGETS = (TAGGED, PACKED)
PREFIX_F64 = 0x44F9110
PREFIX_WORD = 0x44F9180
PREFIXES = (PREFIX_F64, PREFIX_WORD)
NAMES = {TAGGED: "vault_tagged_writer", PACKED: "vault_msgpack_writer", PREFIX_F64: "prefix_f64_writer", PREFIX_WORD: "prefix_word_writer"}
PREFIX_KEY = {PREFIX_F64: (0x7D07D4, 17), PREFIX_WORD: (0x7D08A9, 13)}
TAIL_MARK = (0x7A7A7A7A11111111, 0x7A7A7A7A22222222, 0x7A7A7A7A33333333)

OK_TAG = 0x8000000000000004
ERR_TAG = 0x8000000000000000
BEGIN_OK = 2
WORD_OK = 2
MASK64 = (1 << 64) - 1

OBJ = HEAP_BASE + 0x1000
OBJ_SIZE = 0xC0
SER = HEAP_BASE + 0x2000
OUT = HEAP_BASE + 0x3000
OUT_SIZE = 0x18
BUF = HEAP_BASE + 0x4000
BUF_SIZE = 0x400
STRS = HEAP_BASE + 0x6000
STRS_SIZE = 0x400
USED = 0x8000
GROW_SLACK = 0x40

# address -> (name, result convention, argument decoding)
TAGGED_CALLS = {
    0x3D4F6D0: ("begin_a", "begin", (("P", RSI), ("I", RDX))),
    0x3D50270: ("begin_b", "begin", (("P", RSI), ("I", RDX))),
    0x41C6110: ("write_str", "word", (("P", RDI), ("S", RSI, RDX))),
    0x41B0A80: ("write_time", "rec", (("P", RSI), ("D", RDX))),
    0x4200500: ("write_user", "rec", (("P", RSI), ("P", RDX))),
    0x44F6AC0: ("write_states", "rec", (("P", RSI), ("P", RDX))),
    0x44F9110: ("write_commission", "rec", (("P", RSI), ("F",))),
    0x44FB6F0: ("write_keyed", "rec", (("P", RSI), ("K", RDX, RCX), ("I", R8))),
    0x44FAEC0: ("write_lockup", "rec", (("P", RSI), ("F",))),
    0x44F8060: ("write_extra", "rec", (("P", RSI), ("P", RDX))),
    0x44FC0B0: ("write_relationship", "rec", (("P", RSI), ("I", RDX))),
}
PACKED_CALLS = {
    0x41C6610: ("write_str", "word", (("P", RDI), ("S", RSI, RDX))),
    0x41B0E20: ("write_time", "rec", (("P", RSI), ("D", RDX))),
    0x4200580: ("write_user", "rec", (("P", RSI), ("P", RDX))),
    0x44FAD20: ("write_states", "rec", (("P", RSI), ("P", RDX))),
    0x44FAF30: ("write_commission", "rec", (("P", RSI), ("F",))),
    0x44FBE10: ("write_keyed", "rec", (("P", RSI), ("K", RDX, RCX), ("I", R8))),
    0x44F9E90: ("write_lockup", "rec", (("P", RSI), ("I", RDX))),
    0x44F5FB0: ("write_extra", "rec", (("P", RSI), ("P", RDX))),
    0x44FA3C0: ("write_relationship", "rec", (("P", RSI), ("I", RDX))),
    0x43BD910: ("reserve", "reserve", (("P", RDI), ("I", RSI), ("I", RDX), ("I", RCX), ("I", R8))),
}
PREFIX_CALLS = {0x41C6110: TAGGED_CALLS[0x41C6110]}
TAIL_CALLS = {
    0x4199450: ("tail_f64", "tail", (("P", RSI), ("F",))),
    0x3C6F4E0: ("tail_value", "tail", (("I", RSI), ("P", RDX))),
}
ALL_CALLS = dict(TAGGED_CALLS)
ALL_CALLS.update(PACKED_CALLS)
ALL_CALLS.update(TAIL_CALLS)
ENTRY_CALLS = {TAGGED: TAGGED_CALLS, PACKED: PACKED_CALLS}

KEYS = {
    "name": (0x45A108, 4), "description": (0x7D05B1, 11), "create_time": (0x7D07AE, 11), "vault_user": (0x7D07B9, 10),
    "leader": (0x7D07C3, 6), "is_closed": (0x7D07E5, 9), "allow_deposits": (0x7D07FD, 14),
    "always_close_on_withdraw": (0x7D0817, 24),
}

F_NAME, F_DESC, F_TIME, F_USER, F_LEADER, F_STATES = 0x28, 0x40, 0x80, 0x8C, 0xA0, 0x50
F_COMM, F_LOCK, F_CLOSED, F_ALLOW, F_ALWAYS, F_REL = 0x70, 0x78, 0xB4, 0xB5, 0xB6, 0xB7

FLAG_AT = {TAGGED: 0xB, PACKED: 0x1B}

# Wrong readings of the rule list. Every one of them has to be refused by the byte runs.
MODEL_MUTANTS = (
    "hdr_not_inverted", "hdr_const", "named_nonzero", "name_from_desc", "skip_extra", "states_off", "user_off", "leader_off",
    "comm_off", "closed_u8", "allow_u32", "always_off", "rel_off", "reserve_lt", "reserve_never", "reserve_n_off", "err_word_tag",
    "err_rec_tag", "begin_swapped", "swap_closed_lock", "key_text", "ok_clears_out", "extra_obj8", "time_off", "no_err_stop",
    "prefix_flag_inverted", "prefix_key_short", "prefix_tail_drops_value",
)

# (address, expected original bytes, replacement bytes, label)
CODE_PATCHES = (
    (0x44A686B, b"\x8c", b"\x90", "tagged user offset 0x8c -> 0x90"),
    (0x44A6C1D, b"\xa0", b"\xa4", "packed leader offset 0xa0 -> 0xa4"),
    (0x44A6770, b"\x01", b"\x02", "tagged named test 1 -> 2"),
    (0x44A6CAF, b"\xb5", b"\xb4", "packed allow offset 0xb5 -> 0xb4"),
    (0x44A6AC3, b"\x85", b"\x84", "packed name error jump inverted"),
    (0x44A678A, b"\x02", b"\x03", "tagged name compare 2 -> 3"),
    (0x44A6A4A, b"\x8d", b"\x8c", "packed header or 0x8d -> 0x8c"),
    (0x44A6A93, b"\x03", b"\x04", "packed 4 byte room test 3 -> 4"),
    (0x44A690B, b"\x09", b"\x0a", "tagged is_closed key length 9 -> 10"),
    (0x44A6E34, b"\x0b", b"\x0c", "packed reserve count 11 -> 12"),
    (0x44A68C8, b"\x50", b"\x58", "tagged states offset 0x50 -> 0x58"),
    (0x44A6C54, b"\x70", b"\x78", "packed commission offset 0x70 -> 0x78"),
    (0x44F9115, b"\x84", b"\x85", "prefix f64 flag jump inverted"),
    (0x44F9126, b"\x11", b"\x10", "prefix f64 key length 17 -> 16"),
    (0x44F918E, b"\x00", b"\x01", "prefix word flag compare 0 -> 1"),
    (0x44F9199, b"\x0d", b"\x0c", "prefix word key length 13 -> 12"),
)


class JumpMachine(Machine):
    """The shared evaluator plus recording stubs for tail jumps (plain or conditional) that leave the function."""

    def __init__(self, image, patches=None):
        super().__init__(image, patches)
        self.jumps = {}

    def step(self, row):
        if row.op in ("jmp", "jcc") and row.target in self.jumps and (row.op == "jmp" or self.condition(row.cc)):
            self.stub(self.jumps[row.target])
            return self.pop()
        return super().step(row)


class Case:
    __slots__ = ("name", "entry", "obj", "strs", "flag", "cap", "length", "fail_at", "fail")

    def __init__(self, name, entry, obj, strs, flag, cap, length, fail_at, fail):
        self.name, self.entry, self.obj, self.strs, self.flag = name, entry, obj, strs, flag
        self.cap, self.length, self.fail_at, self.fail = cap, length, fail_at, fail


def pattern(size, seed):
    return bytes((seed + index * 7) & 0xFF for index in range(size))


def get64(blob, at):
    return struct.unpack_from("<Q", blob, at)[0]


def key_bytes(image, label):
    va, size = KEYS[label]
    start = image.offset(va)
    data = bytes(image.blob[start:start + size])
    if data.decode("ascii") != label:
        raise EvidenceError("key text mismatch for " + label)
    return data


# ---------------------------------------------------------------------------------------------------------------------------
# Rule list (written from the field order and branch conditions, not from the stub log).
# ---------------------------------------------------------------------------------------------------------------------------

class Stop(Exception):
    pass


class Predicted:
    def __init__(self, initial_out):
        self.log = []
        self.out = bytearray(initial_out)
        self.cap = 0
        self.length = 0
        self.buf = bytearray()


def packed_header(flag, m):
    if "hdr_const" in m:
        return 0x9D
    inverted = flag if "hdr_not_inverted" in m else flag ^ 1
    return ((inverted << 4) & 0xFF) | 0x8D


def model(image, case, m=frozenset()):
    packed = case.entry == PACKED
    keys = {label: key_bytes(image, label) for label in KEYS}
    if "key_text" in m:
        keys["allow_deposits"] = b"allow_deposit"
    p = Predicted(pattern(OUT_SIZE, 0x60))
    p.cap, p.length = (case.cap, case.length) if packed else (0, 0)
    p.buf = bytearray(pattern(BUF_SIZE, 0x21))
    obj = case.obj
    flag = case.flag
    named = flag != 0 if "named_nonzero" in m else flag == 1
    state = {"calls": 0}

    def text(at):
        ptr, size = get64(obj, at), get64(obj, at + 8)
        if STRS <= ptr and ptr + size <= STRS + STRS_SIZE:
            return case.strs[ptr - STRS:ptr - STRS + size]
        return ("wild", ptr, size)

    def ptr_arg(offset):
        return ("obj", offset)

    def call(name, args, kind):
        p.log.append((name,) + tuple(args))
        index = state["calls"]
        state["calls"] += 1
        if case.fail_at == index and "no_err_stop" not in m:
            e0, e1, e2 = case.fail
            if kind == "word":
                e0 = e0 if e0 != WORD_OK else e0 + 1
                tag = OK_TAG if "err_word_tag" in m else ERR_TAG
                p.out[:] = struct.pack("<QQQ", tag, e0, e1)
            elif kind == "begin":
                e0 = e0 if e0 != BEGIN_OK else e0 + 1
                p.out[:] = struct.pack("<QQQ", ERR_TAG, e0, e1)
            else:
                e0 = e0 if e0 != OK_TAG else e0 ^ 1
                p.out[:] = struct.pack("<QQQ", ERR_TAG if "err_rec_tag" in m else e0, e1, e2)
            raise Stop

    def put_byte(value):
        if p.cap == p.length and "reserve_never" not in m:
            p.log.append(("reserve", "ser", p.length, 1, 1, 1))
            p.cap = p.length + 1 + GROW_SLACK
        p.buf[p.length] = value
        p.length += 1

    def put_run(data, count=None):
        count = len(data) if count is None else count
        if "reserve_n_off" in m and count == 11:
            count = 10
        short = p.cap - p.length < count if "reserve_lt" not in m else p.cap - p.length < count - 1
        if short and "reserve_never" not in m:
            p.log.append(("reserve", "ser", p.length, count, 1, 1))
            p.cap = p.length + count + GROW_SLACK
        p.buf[p.length:p.length + len(data)] = data
        p.length += len(data)

    def inline_key(tag, label):
        if packed and named:
            put_byte(tag)
            put_run(keys[label])

    def key_call(label):
        if named:
            call("write_str", ("ser", ("S", keys[label])), "word")

    def u8(at):
        return obj[at]

    def u32(at):
        return struct.unpack_from("<I", obj, at)[0]

    def f(at):
        return get64(obj, at)

    try:
        if packed:
            put_byte(packed_header(flag, m))
        else:
            begin = "begin_b" if flag == 0 else "begin_a"
            if "begin_swapped" in m:
                begin = "begin_a" if flag == 0 else "begin_b"
            call(begin, ("ser", 0xD), "begin")
        # name, description
        name_at = F_DESC if "name_from_desc" in m else F_NAME
        if packed:
            inline_key(0xA4, "name")
            call("write_str", ("ser", ("S", text(name_at))), "word")
            inline_key(0xAB, "description")
            call("write_str", ("ser", ("S", text(F_DESC))), "word")
            inline_key(0xAB, "create_time")
        else:
            key_call("name")
            call("write_str", ("ser", ("S", text(name_at))), "word")
            key_call("description")
            call("write_str", ("ser", ("S", text(F_DESC))), "word")
            key_call("create_time")
        call("write_time", ("ser", ("obj", 0x88 if "time_off" in m else F_TIME)), "rec")
        if packed:
            if named:
                call("write_str", ("ser", ("S", keys["vault_user"])), "word")
        else:
            key_call("vault_user")
        call("write_user", (ptr_arg(0x90 if "user_off" in m else F_USER), "ser"), "rec")
        if named:
            call("write_str", ("ser", ("S", keys["leader"])), "word")
        call("write_user", (ptr_arg(0xA4 if "leader_off" in m else F_LEADER), "ser"), "rec")
        call("write_states", ("ser", ptr_arg(0x58 if "states_off" in m else F_STATES)), "rec")
        call("write_commission", ("ser", f(F_LOCK if "comm_off" in m else F_COMM)), "rec")
        closed = ("write_keyed", ("ser", ("K", keys["is_closed"]), u8(F_CLOSED) if "closed_u8" in m else u32(F_CLOSED)), "rec")
        lockup = ("write_lockup", ("ser", f(F_LOCK)), "rec")
        for step in ((lockup, closed) if "swap_closed_lock" in m else (closed, lockup)):
            call(*step)
        call("write_keyed", ("ser", ("K", keys["allow_deposits"]), u32(F_ALLOW) if "allow_u32" in m else u8(F_ALLOW)), "rec")
        if "skip_extra" not in m:
            call("write_extra", ("ser", ptr_arg(8 if "extra_obj8" in m else 0)), "rec")
        call("write_keyed", ("ser", ("K", keys["always_close_on_withdraw"]), u8(0xB7 if "always_off" in m else F_ALWAYS)), "rec")
        call("write_relationship", ("ser", u8(0xB6 if "rel_off" in m else F_REL)), "rec")
        p.out[0:8] = struct.pack("<Q", OK_TAG)
        if "ok_clears_out" in m:
            p.out[8:] = bytes(16)
    except Stop:
        pass
    return p


# ---------------------------------------------------------------------------------------------------------------------------
# Byte runs.
# ---------------------------------------------------------------------------------------------------------------------------

class Harness:
    def __init__(self, image, patches=None, drop=None):
        self.image = image
        self.machine = JumpMachine(image, patches)
        for address in ALL_CALLS:
            if address == drop:
                continue
            if address in TAIL_CALLS:
                self.machine.jumps[address] = self.hook(address)
            else:
                self.machine.calls[address] = self.hook(address)
        self.case = None
        self.log = []
        self.failable = 0

    def classify(self, value):
        if value == SER:
            return "ser"
        if OBJ <= value < OBJ + OBJ_SIZE:
            return ("obj", value - OBJ)
        if STACK_TOP - base.STACK_SIZE <= value < STACK_TOP:
            return "stk"
        return ("raw", value)

    def decode_args(self, spec):
        machine = self.machine
        regs = machine.regs
        out = []
        for item in spec:
            kind = item[0]
            if kind == "P":
                out.append(self.classify(regs[item[1]]))
            elif kind == "I":
                out.append(regs[item[1]])
            elif kind == "S":
                ptr, size = regs[item[1]], regs[item[2]]
                out.append(("S", machine.memory.bytes_at(ptr, size) if size <= 0x100 else ("wild", ptr, size)))
            elif kind == "K":
                ptr, size = regs[item[1]], regs[item[2]]
                out.append(("K", machine.memory.bytes_at(ptr, size) if size <= 0x100 else ("wild", ptr, size)))
            elif kind == "F":
                out.append(machine.xmm[0] & MASK64)
            elif kind == "D":
                slot = machine.memory.read(regs[item[1]], 8)
                out.append(self.classify(machine.memory.read(slot, 8)))
        return tuple(out)

    def hook(self, address):
        name, kind, spec = ALL_CALLS[address]

        def run(machine):
            regs = machine.regs
            memory = machine.memory
            self.log.append((name,) + self.decode_args(spec))
            if kind == "reserve":
                ser, length, count = regs[RDI], regs[RSI], regs[RDX]
                memory.write(ser, 8, (length + count + GROW_SLACK) & MASK64)
                return
            if kind == "tail":
                for step, word in enumerate(TAIL_MARK):
                    memory.write(regs[RDI] + 8 * step, 8, word)
                return
            index = self.failable
            self.failable += 1
            failing = self.case.fail_at == index
            e0, e1, e2 = self.case.fail
            if kind == "word":
                regs[base.RAX] = (e0 if e0 != WORD_OK else e0 + 1) if failing else WORD_OK
                regs[RDX] = e1 if failing else 0
                machine.keep_rdx = True
            elif kind == "begin":
                memory.write(regs[RDI], 8, (e0 if e0 != BEGIN_OK else e0 + 1) if failing else BEGIN_OK)
                memory.write(regs[RDI] + 8, 8, e1)
            else:
                memory.write(regs[RDI], 8, (e0 if e0 != OK_TAG else e0 ^ 1) if failing else OK_TAG)
                memory.write(regs[RDI] + 8, 8, e1)
                memory.write(regs[RDI] + 16, 8, e2)

        return run

    def run(self, case):
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        machine.xmm = [base.POISON | base.POISON << 64] * 16
        self.case, self.log, self.failable = case, [], 0
        ser = bytearray(pattern(0x40, 0x11))
        if case.entry == PACKED:
            struct.pack_into("<QQQ", ser, 0, case.cap, BUF, case.length)
        ser[FLAG_AT[case.entry]] = case.flag
        memory.put_bytes(OBJ, case.obj)
        memory.put_bytes(STRS, case.strs)
        memory.put_bytes(SER, bytes(ser))
        memory.put_bytes(BUF, pattern(BUF_SIZE, 0x21))
        memory.put_bytes(OUT, pattern(OUT_SIZE, 0x60))
        before = bytes(memory.heap[:USED])
        value = machine.run(case.entry, {RDI: OUT, RSI: OBJ, RDX: SER})
        after = bytes(memory.heap[:USED])
        if value != OUT:
            raise Halt("result pointer")
        spans = [(OUT - HEAP_BASE, OUT_SIZE), (BUF - HEAP_BASE, BUF_SIZE)]
        if case.entry == PACKED:
            spans.append((SER - HEAP_BASE, 0x18))
        cursor = 0
        for start, size in sorted(spans):
            if before[cursor:start] != after[cursor:start]:
                raise Halt("state changed outside the result, ser words and buffer")
            cursor = start + size
        if before[cursor:] != after[cursor:]:
            raise Halt("state changed outside the result, ser words and buffer")
        o, s, b = OUT - HEAP_BASE, SER - HEAP_BASE, BUF - HEAP_BASE
        cap, ptr, length = struct.unpack_from("<QQQ", after, s) if case.entry == PACKED else (0, BUF, 0)
        if ptr != BUF:
            raise Halt("buffer pointer moved")
        return {"log": self.log, "out": after[o:o + OUT_SIZE], "cap": cap, "length": length, "buf": after[b:b + BUF_SIZE]}


def prefix_run(harness, case):
    """Run one prefix writer: rdi result, rsi serializer, rdx word value (xmm0 carries the f64 for 0x44f9110)."""
    machine = harness.machine
    memory = machine.memory
    memory.reset(USED)
    machine.xmm = [base.POISON | base.POISON << 64] * 16
    harness.case, harness.log, harness.failable = case, [], 0
    ser = bytearray(pattern(0x40, 0x11))
    ser[0xB] = case.flag
    value = get64(case.obj, 0)
    memory.put_bytes(SER, bytes(ser))
    memory.put_bytes(OUT, pattern(OUT_SIZE, 0x60))
    before = bytes(memory.heap[:USED])
    machine.xmm[0] = value
    machine.run(case.entry, {RDI: OUT, RSI: SER, RDX: value})
    after = bytes(memory.heap[:USED])
    o = OUT - HEAP_BASE
    if before[:o] != after[:o] or before[o + OUT_SIZE:] != after[o + OUT_SIZE:]:
        raise Halt("prefix writer touched memory outside the result")
    return {"log": harness.log, "out": after[o:o + OUT_SIZE], "cap": 0, "length": 0, "buf": b""}


def prefix_model(image, case, m=frozenset()):
    start, size = PREFIX_KEY[case.entry]
    if "prefix_key_short" in m:
        size -= 1
    key = bytes(image.blob[image.offset(start):image.offset(start) + size])
    value = get64(case.obj, 0)
    p = Predicted(pattern(OUT_SIZE, 0x60))
    keyed = case.flag == 0 if "prefix_flag_inverted" in m else case.flag != 0
    if keyed:
        p.log.append(("write_str", "ser", ("S", key)))
        if case.fail_at == 0:
            e0, e1, _ = case.fail
            p.out[:] = struct.pack("<QQQ", ERR_TAG, e0 if e0 != WORD_OK else e0 + 1, e1)
            return p
    if case.entry == PREFIX_F64:
        p.log.append(("tail_f64", "ser", value))
    else:
        p.log.append(("tail_value", 0 if "prefix_tail_drops_value" in m else value, "ser"))
    p.out[:] = struct.pack("<QQQ", *TAIL_MARK)
    return p


def prefix_cases(count, seed=0x9F1C):
    stream = lcg(seed)
    for index in range(count):
        entry = PREFIXES[index % 2]
        obj = bytearray(OBJ_SIZE)
        obj[0:8] = (next(stream) | next(stream) << 40 & MASK64).to_bytes(8, "little")
        flag = FLAGS[next(stream) % len(FLAGS)]
        fail = tuple(next(stream) | next(stream) << 33 & MASK64 for _ in range(3))
        yield Case("%s-%d" % (NAMES[entry], index), entry, bytes(obj), bytes(STRS_SIZE), flag, 0, 0, None if next(stream) % 3 else 0, fail)


def compare(got, p):
    if got["log"] != p.log:
        return "log"
    if got["out"] != bytes(p.out):
        return "out"
    if got["cap"] != p.cap or got["length"] != p.length:
        return "ser"
    if got["buf"] != bytes(p.buf):
        return "buf"
    return None


# ---------------------------------------------------------------------------------------------------------------------------
# Cases.
# ---------------------------------------------------------------------------------------------------------------------------

def lcg(seed):
    state = seed
    while True:
        state = (state * 0x5851F42D4C957F2D + 0x14057B7EF767814F) & MASK64
        yield state >> 11


FLAGS = (0, 1, 1, 1, 0, 2, 0xFF, 1)
DELTAS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 25, 40, 200)


def make_case(stream, index, entry):
    obj = bytearray(next(stream) & 0xFF for _ in range(OBJ_SIZE))
    for at in range(0, OBJ_SIZE, 8):
        obj[at:at + 8] = (next(stream) | (next(stream) << 40) & MASK64).to_bytes(8, "little")
    strs = bytes(32 + next(stream) % 90 for _ in range(STRS_SIZE))
    for at in (F_NAME, F_DESC):
        start = next(stream) % 0x200
        size = next(stream) % 26 if next(stream) % 9 else 0
        struct.pack_into("<QQ", obj, at, STRS + start, size)
    flag = FLAGS[next(stream) % len(FLAGS)]
    length = next(stream) % 9
    cap = length + DELTAS[next(stream) % len(DELTAS)]
    fail_at = None if next(stream) % 2 else next(stream) % 18
    fail = tuple(next(stream) | (next(stream) << 33) & MASK64 for _ in range(3))
    return Case("%s-%d" % (NAMES[entry], index), entry, bytes(obj), strs, flag, cap, length, fail_at, fail)


def vector_cases(count, seed=0x7A17C0DE):
    stream = lcg(seed)
    for index in range(count):
        yield make_case(stream, index, TARGETS[index % 2])


def canonical_cases():
    strs = bytes(range(32, 32 + 64)) * 16
    for entry in TARGETS:
        for flag in (0, 1):
            obj = bytearray(pattern(OBJ_SIZE, 3))
            struct.pack_into("<QQ", obj, F_NAME, STRS + 3, 5)
            struct.pack_into("<QQ", obj, F_DESC, STRS + 20, 7)
            yield Case("canonical-%s-flag%d" % (NAMES[entry], flag), entry, bytes(obj), strs, flag, 0x200, 0, None, (0, 0, 0))


# ---------------------------------------------------------------------------------------------------------------------------
# Evidence.
# ---------------------------------------------------------------------------------------------------------------------------

def site_rows(image):
    rows = []
    for entry in TARGETS + PREFIXES:
        start, end = image.exact_fde(entry)
        insns = decode_range(image, start, end)
        targets = {}
        for row in insns:
            if row.op == "call":
                targets[row.target] = targets.get(row.target, 0) + 1
        rows.append((NAMES[entry], "%#x" % start, "%#x" % end, end - start, len(insns),
                     " ".join("%#x:%d" % (t, n) for t, n in sorted(targets.items()))))
    return rows


def canonical_rows(image):
    rows = []
    for case in canonical_cases():
        p = model(image, case)
        for index, item in enumerate(p.log):
            rows.append((case.name, index, item[0], repr(item[1:])))
    return rows


def failure_rows(image, harness):
    """Per entry and flag, inject a failure at every stub call in turn and record the 24 byte result record."""
    rows = []
    for ok_case in canonical_cases():
        calls = [item[0] for item in harness.run(ok_case)["log"] if item[0] != "reserve"]
        for index, callee in enumerate(calls):
            case = Case(ok_case.name, ok_case.entry, ok_case.obj, ok_case.strs, ok_case.flag, ok_case.cap, ok_case.length, index,
                        (0x1111111111111111, 0x2222222222222222, 0x3333333333333333))
            got = harness.run(case)
            if compare(got, model(image, case)):
                raise EvidenceError("failure record disagrees for %s at %d" % (case.name, index))
            rows.append((ok_case.name, index, callee, got["out"].hex(), len(got["log"])))
    return rows


def reserve_rows(image, harness):
    """Packed writer: every spare-capacity value from 0 to 14 at several starting lengths, with the growth requests it triggers."""
    rows = []
    base_case = [case for case in canonical_cases() if case.entry == PACKED and case.flag == 1][0]
    for length in (0, 3):
        for spare in range(15):
            case = Case(base_case.name, PACKED, base_case.obj, base_case.strs, 1, length + spare, length, None, (0, 0, 0))
            got = harness.run(case)
            if compare(got, model(image, case)):
                raise EvidenceError("reserve rows disagree at %d/%d" % (length, spare))
            asks = [(item[2], item[3]) for item in got["log"] if item[0] == "reserve"]
            rows.append((length, spare, len(asks), " ".join("%d+%d" % pair for pair in asks), got["length"]))
    return rows


TEXT_WORDS = (F_NAME, F_DESC)


def influence_rows(image, harness):
    """Flip bit 0 of each record byte in turn and list the stub calls whose logged arguments change.

    A record byte that no call sees is only passed on by pointer; the byte runs and the rule list must agree on every flip.
    """
    rows = []
    for case in canonical_cases():
        baseline = harness.run(case)["log"]
        for offset in range(OBJ_SIZE):
            if any(word + 1 <= offset < word + 16 and offset not in (word + 8,) for word in TEXT_WORDS):
                continue
            obj = bytearray(case.obj)
            obj[offset] ^= 1
            probe = with_obj(case, bytes(obj))
            got = harness.run(probe)
            if compare(got, model(image, probe)):
                raise EvidenceError("influence probe disagrees for %s at %#x" % (case.name, offset))
            changed = [index for index, (a, b) in enumerate(zip(baseline, got["log"])) if a != b]
            if changed:
                rows.append((case.name, "%#x" % offset, " ".join(str(i) for i in changed),
                             " ".join(baseline[i][0] for i in changed)))
    return rows


def with_obj(case, obj):
    return Case(case.name, case.entry, obj, case.strs, case.flag, case.cap, case.length, case.fail_at, case.fail)


def digest(got):
    text = repr((got["log"], got["out"].hex(), got["cap"], got["length"], got["buf"].hex()))
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def verify_tables(image):
    for label in KEYS:
        key_bytes(image, label)
    for entry, table in ENTRY_CALLS.items():
        start, end = image.exact_fde(entry)
        called = {row.target for row in decode_range(image, start, end) if row.op == "call"}
        if called != set(table):
            raise EvidenceError("callee set differs for %#x" % entry)


def verify_prefix_tables(image):
    for entry in PREFIXES:
        start, end = image.exact_fde(entry)
        rows = decode_range(image, start, end)
        if {row.target for row in rows if row.op == "call"} != set(PREFIX_CALLS):
            raise EvidenceError("prefix callee set differs for %#x" % entry)
        tails = {row.target for row in rows if row.op in ("jmp", "jcc") and not start <= row.target < end}
        if tails != {0x4199450 if entry == PREFIX_F64 else 0x3C6F4E0}:
            raise EvidenceError("prefix tail target differs for %#x" % entry)


def run_cases(image, harness, count, keep, sample_rows):
    mismatches = 0
    first = []
    seen_branch = {"error": 0, "ok": 0, "reserve": 0, "named": 0, "compact": 0}
    for index, case in enumerate(vector_cases(count)):
        got = harness.run(case)
        p = model(image, case)
        if compare(got, p):
            mismatches += 1
            if len(first) < 5:
                first.append(case.name)
        if index < keep:
            first_call = got["log"][0][0] if got["log"] else ""
            sample_rows.append((case.name, "%#x" % case.entry, case.flag, case.cap, case.length, case.fail_at if case.fail_at is not None else "-",
                                len(got["log"]), got["out"][:8].hex(), got["length"], digest(got), first_call))
        seen_branch["ok" if got["out"][:8] == struct.pack("<Q", OK_TAG) else "error"] += 1
        seen_branch["reserve"] += any(item[0] == "reserve" for item in got["log"])
        seen_branch["named" if case.flag == 1 else "compact"] += 1
    return mismatches, first, seen_branch


def negative_rows(image, pool):
    """Each wrong rule list, each corrupted code byte and each out of range input; returns rows of (label, kind, detected)."""
    harness = Harness(image)
    real = []
    for case in pool:
        real.append((case, harness.run(case)))
    rows = []
    prefix_real = [(case, prefix_run(harness, case)) for _, case in zip(range(200), prefix_cases(200, seed=0x44))]
    for variant in MODEL_MUTANTS:
        hit = ""
        if variant.startswith("prefix_"):
            for case, got in prefix_real:
                if compare(got, prefix_model(image, case, frozenset((variant,)))):
                    hit = case.name
                    break
            rows.append((variant, "rule list", 1 if hit else 0, hit))
            continue
        for case, got in real:
            if compare(got, model(image, case, frozenset((variant,)))):
                hit = case.name
                break
        rows.append((variant, "rule list", 1 if hit else 0, hit))
    for address, old, new, label in CODE_PATCHES:
        start = image.offset(address)
        if bytes(image.blob[start:start + len(old)]) != old:
            raise EvidenceError("patch site bytes differ at %#x" % address)
        patched = Harness(image, {address + i: b for i, b in enumerate(new)})
        hit = ""
        prefixed = 0x44F9110 <= address < 0x44F91E0
        for case, _ in (prefix_real if prefixed else real):
            try:
                got = prefix_run(patched, case) if prefixed else patched.run(case)
            except (Halt, base.Panicked, IndexError, KeyError, struct.error):
                hit = case.name
                break
            if compare(got, prefix_model(image, case) if prefixed else model(image, case)):
                hit = case.name
                break
        rows.append((label, "code byte", 1 if hit else 0, hit))
    for label, builder in (
        ("entry inside body", lambda: image.exact_fde(TAGGED + 1)),
        ("entry before function", lambda: image.exact_fde(PACKED - 1)),
        ("entry outside file", lambda: image.exact_fde(0x7FFFFFFFFF)),
        ("wrong digest", lambda: check_digest(b"x" * 64)),
        ("key table corrupted", lambda: key_check_corrupt(image)),
    ):
        try:
            builder()
            rows.append((label, "range or digest", 0, ""))
        except EvidenceError:
            rows.append((label, "range or digest", 1, "refused"))
    for address in (0x41C6110, 0x44FB6F0, 0x44FBE10):
        dropped = Harness(image, drop=address)
        hit = ""
        for case, _ in real:
            if case.entry != (TAGGED if address in TAGGED_CALLS else PACKED):
                continue
            try:
                dropped.run(case)
            except Halt:
                hit = case.name
                break
        rows.append(("callee %#x unmodelled" % address, "stub table", 1 if hit else 0, hit))
    return rows


def check_digest(blob):
    if hashlib.sha256(blob).hexdigest() != base.SHA256:
        raise EvidenceError("binary SHA-256 mismatch")


def key_check_corrupt(image):
    saved = KEYS["leader"]
    KEYS["leader"] = (saved[0] + 1, saved[1])
    try:
        key_bytes(image, "leader")
    finally:
        KEYS["leader"] = saved


def run_prefix_cases(image, harness, count, samples):
    mismatches, ok = 0, 0
    for index, case in enumerate(prefix_cases(count)):
        got = prefix_run(harness, case)
        mismatches += 1 if compare(got, prefix_model(image, case)) else 0
        ok += got["out"][:8] != struct.pack("<Q", ERR_TAG)
        if index < 40:
            samples.append((case.name, "%#x" % case.entry, case.flag, "-", "-", case.fail_at if case.fail_at is not None else "-",
                            len(got["log"]), got["out"][:8].hex(), "-", digest(got), got["log"][0][0]))
    return mismatches, ok


def analyse(image, count=10400, pool_size=900, prefix_count=800):
    verify_tables(image)
    verify_prefix_tables(image)
    harness = Harness(image)
    samples = []
    mismatches, first, branches = run_cases(image, harness, count, 400, samples)
    extra_mismatches, branches["prefix_ok"] = run_prefix_cases(image, harness, prefix_count, samples)
    mismatches += extra_mismatches
    count += prefix_count
    pool = [case for _, case in zip(range(pool_size), vector_cases(pool_size, seed=0x51ED))]
    negatives = negative_rows(image, pool)
    detected = sum(row[2] for row in negatives)
    return {
        "sites": site_rows(image), "canonical": canonical_rows(image), "failures": failure_rows(image, harness),
        "reserves": reserve_rows(image, harness), "influence": influence_rows(image, harness), "samples": samples, "negatives": negatives,
        "mismatches": mismatches, "first": first, "branches": branches, "cases": count, "detected": detected,
    }


def render(result):
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(c) for c in row) for row in result[rows]]) + "\n"

    tsv("sites.tsv", ("function", "fde_start", "fde_end", "bytes", "instructions", "call_targets"), "sites")
    tsv("canonical_calls.tsv", ("case", "index", "callee", "arguments"), "canonical")
    tsv("record_influence.tsv", ("case", "flipped_record_offset", "changed_call_indices", "changed_callees"), "influence")
    tsv("failure_records.tsv", ("case", "fail_index", "failing_callee", "result_record_hex", "stub_calls_made"), "failures")
    tsv("reserve_requests.tsv", ("start_length", "spare_capacity", "requests", "request_len_plus_count", "final_length"), "reserves")
    tsv("cases_sample.tsv", ("case", "entry", "flag", "capacity", "length", "fail_at", "stub_calls", "out_tag", "final_length", "digest", "first_call"), "samples")
    tsv("negatives.tsv", ("label", "kind", "detected", "first_detecting_case"), "negatives")
    summary = {
        "binary_sha256": base.SHA256, "cases": result["cases"], "mismatches": result["mismatches"], "branches": result["branches"],
        "negative_controls": len(result["negatives"]), "negative_detected": result["detected"],
    }
    files["summary.json"] = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    measure = {"cases": result["cases"] - result["mismatches"], "negative_controls": len(result["negatives"]),
               "negative_detected": result["detected"]}
    files["measure.json"] = json.dumps(measure, indent=2, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args(argv)
    image = load_image()
    result = analyse(image)
    if result["mismatches"]:
        raise SystemExit("rule list disagrees with the bytes on %d cases: %s" % (result["mismatches"], result["first"]))
    files = render(result)
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
