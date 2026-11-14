#!/usr/bin/env python3
"""Reconstruct the node #115 BOLE reserve reply 0x38e64b0: the bytes run from the ELF against a separately written rule list.

0x38e64b0 is the callback stored for address 0x...0812 in the read table at 0x646e758. It charges 1000 + 33 per input byte, parses one
token index, finds the token record in an ordered map (a B-tree or a sorted ring), calls the merged rate and utilization bodies
(0x36a0b30, 0x36a08b0, 0x36a09f0) and returns eight 32 byte big-endian words. The real bytes run in the shared offline interpreter
(tools/x86_115.py) with every external call as a recording stub; a rule list written separately predicts the result words, the reply
bytes, every heap byte and the ordered stub requests. Wrong readings of the rule list and byte edits of the body are run as negative
controls. No objdump or readelf output is parsed and the binary is never executed. Standard library only.

    python3 tools/bole_reserve_reply115.py --out <dir>
"""

import argparse
import hashlib
import json
import math
import pathlib
import struct
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import bole_rate115 as rate  # noqa: E402  (merged rule list of the four callees)
from x86_115 import (  # noqa: E402
    HEAP_BASE, MARK_BASE, POISON, R8, RAX, RCX, RDI, RDX, RSI, SHA256, EvidenceError, Halt, Machine, Panicked, decode_range,
    load_image, to_bits, to_float,
)

ENTRY = 0x38E64B0
BODY_END = 0x38E6C70  # first landing pad; [BODY_END, FDE end) is unwind cleanup and is not run
TABLE_SLOT = 0x646E758
PARSE, DROP_PARSE, FMT_A, DROP_CODE, LOOKUP = 0x3897200, 0x38F9750, 0x46DE430, 0x3D57B80, 0x4556410
RATE, UTIL_WORD, UTIL_F64 = 0x36A0B30, 0x36A08B0, 0x36A09F0
SLOT_ALLOC, SLOT_FREE, SLOT_ALLOC_ERR, SLOT_BYTES, SLOT_DIV = 0x64DF480, 0x64DF4A0, 0x64DF498, 0x64DF948, 0x64DFAF8
SLOT_UTIL_F64, SLOT_FMT_B = 0x64E8D50, 0x64E9570
SLOT_TARGETS = {SLOT_ALLOC: 0x6355830, SLOT_FREE: 0x635DE30, SLOT_ALLOC_ERR: 0x141E264, SLOT_BYTES: 0x161CC70, SLOT_DIV: 0x63EFEC0,
                SLOT_UTIL_F64: UTIL_F64, SLOT_FMT_B: 0x3D4EB60}
CONSTANTS = {0x451210: "u64 to f64 high lane words", 0x450170: "u64 to f64 lane biases", 0x4599C8: "-1e14", 0x4592B0: "1.0",
             0x459090: "2^64", 0x459360: "2^63", 0x458D58: "largest f64 below 2^64"}

E10, E14, TOP = 10 ** 10, 10 ** 14, (1 << 64) - 1
OUT_OF_GAS = 0x8000000000000001
BTREE_TAG = 0x8000000000000000
REPLY_SIZE, BOX_SIZE, TEXT = 0x100, 0x20, b"Invalid input"
BASE_GAS, GAS_PER_BYTE, MAX_INPUT = 1000, 33, 2000
MUL_E10 = 0xDBE6FECEBDEDD5BF

# Fixture addresses inside the interpreter heap.
OUT, CTX, HOLD_A, HOLD_B, INPUT, VTABLE = (HEAP_BASE + offset for offset in (0x100, 0x200, 0x300, 0x400, 0x800, 0x1800))
ALLOCS, STORE = HEAP_BASE + 0x2000, HEAP_BASE + 0x4000
USED = 0x20000
NODE_SIZE, VALUE_SIZE, ENTRY_SIZE = 0x858, 0xB0, 0xB8
KEYS_AT, LEN_AT, EDGES_AT = 0x798, 0x7F2, 0x7F8
DATA_WORD = 0x5150
MARK_DROP = MARK_BASE + 0x99000

VARIANTS = (
    "gas_32", "gas_base_0", "len_2001", "gas_no_reply", "gas_wrap", "count_le", "parse_any_tag", "miss_code_swap", "ring_bit_first",
    "ring_full_second", "ring_no_len", "ring_no_wrap", "rate_i64", "rate_u32", "reserve_e10", "reserve_plus", "no_reserve", "util_word_f64",
    "supply_round", "nan_max", "neg_wrap", "over_wrap", "opt_raw", "opt_always", "opt_tag_any", "swap_10_18", "swap_totals", "ceil_borrow",
    "no_total_guard", "guard_ge", "little_endian", "word_order", "util_error_ok", "box_free_first", "text_len_12",
)


def fmt_words(code, extra):
    """What the two message-building stubs answer: three words that name the request."""
    return (0xC0DE0000 | code, 0xFACE0000 | (extra & 0xFFFF), 0xBEEF0000 | ((extra >> 16) & 0xFFFF))


def i32(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & 0x80000000 else value


class Case:
    """One call. Defaults describe a found token in a one-leaf tree and real callees."""

    def __init__(self, name, **fields):
        self.name = name
        self.input_len, self.gas = 32, 1 << 40
        self.parse = ("ok", 7)
        self.count = 100
        self.store = ("tree", 0, 3)  # ("tree", height, separators) / ("ring", capacity, head) / ("none",)
        self.keys = [7]
        self.rec = rate.record(a=50, b=100)
        self.tag = None  # the dword at record +0; None follows rec["ltv"]
        self.reserve = 10 ** 13
        self.lookups = None  # injected (rax, rdx) answers of the ring search
        self.callee = None  # injected callee answers: dict(rate=, util_word=(tag, word), util_f64=(tag, bits))
        self.faults = {}  # injected 128 bit quotients by request index
        self.fail_alloc = None
        self.reply_len = REPLY_SIZE  # the length the bytes constructor reports
        for key, value in fields.items():
            if not hasattr(self, key):
                raise KeyError(key)
            setattr(self, key, value)

    def token(self):
        return self.parse[1]


def other_record(key):
    """Neighbour records differ from the subject so a wrong slot shows."""
    return rate.record(a=(key * 7 + 3) % 97, b=100 + key % 13, mn=key % 5 * 10 ** 11, ltv=key * E10 + 5, px=key + 1000, bal=key + 2000)


def record_of(case, key):
    return case.rec if key == case.token() else other_record(key)


def record_bytes(rec, tag=None):
    data = bytearray((0x31 + 7 * index) & 0xFF for index in range(VALUE_SIZE))
    if tag is None:
        tag = 2 if rec["ltv"] is None else 1
    struct.pack_into("<Q", data, 0, tag)
    for offset, value in ((8, rec["ltv"] or 0), (0x10, rec["px"]), (0x18, rec["bal"]), (0x40, rec["a"]), (0x58, rec["ia"]), (0x60, rec["b"]),
                          (0x78, rec["ib"]), (0x80, rec["mn"]), (0x88, rec["mx"]), (0x90, rec["kr"]), (0x98, rec["k"])):
        struct.pack_into("<Q", data, offset, value & TOP)
    return bytes(data)


def tree_shape(keys, height, separators):
    """A search tree as nested (keys, children) nodes; children is () for a leaf. Empty nodes are allowed."""
    keys = sorted(keys)
    if height == 0:
        if len(keys) > 11:
            raise ValueError("leaf holds at most 11 keys")
        return (keys, ())
    count = max(1, min(separators, 11, len(keys)))
    if not keys:
        return ([], (tree_shape([], height - 1, separators),))
    rest = len(keys) - count
    sizes = [rest // (count + 1) + (1 if index < rest % (count + 1) else 0) for index in range(count + 1)]
    own, children, at = [], [], 0
    for index, size in enumerate(sizes):
        children.append(tree_shape(keys[at:at + size], height - 1, separators))
        at += size
        if index < count:
            own.append(keys[at])
            at += 1
    return (own, tuple(children))


def tree_find(node, token, height):
    """Returns the path to the key or None, by the rule the walk follows: first key not below the token, equal ends, else go down."""
    own, children = node
    index = 0
    while index < len(own) and token > own[index]:
        index += 1
    if index < len(own) and token == own[index]:
        return True
    if height == 0:
        return None
    return tree_find(children[index], token, height - 1)


class Layout:
    """Writes one case into heap bytes and remembers where each record went."""

    def __init__(self, case):
        self.case = case
        self.data = bytearray(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(USED))
        self.where = {}
        self.next = STORE
        self.put(CTX + 0x10, HOLD_A)
        self.put(CTX + 0x48, HOLD_B)
        self.put(HOLD_A + 0x38, case.count)
        self.put(HOLD_B + 0x78, case.reserve)
        self.put(VTABLE + 0x20, MARK_DROP)
        kind = case.store[0]
        if kind == "tree":
            shape = tree_shape(case.keys, case.store[1], case.store[2])
            self.shape = shape
            self.put(HOLD_B + 0x58, BTREE_TAG)
            self.put(HOLD_B + 0x60, self.node(shape))
            self.put(HOLD_B + 0x68, case.store[1])
        elif kind == "ring":
            capacity, head = case.store[1], case.store[2]
            keys = sorted(case.keys)
            self.put(HOLD_B + 0x58, capacity)
            self.put(HOLD_B + 0x60, STORE)
            self.put(HOLD_B + 0x68, head)
            self.put(HOLD_B + 0x70, len(keys))
            for index, key in enumerate(keys):
                at = STORE + ((head + index) % capacity) * ENTRY_SIZE
                self.put(at, key)
                self.blob(at + 8, record_bytes(record_of(case, key), case.tag if key == case.token() else None))
                self.where[key] = at + 8
        else:
            self.put(HOLD_B + 0x58, BTREE_TAG)
            self.put(HOLD_B + 0x60, 0)
            self.put(HOLD_B + 0x68, case.store[1] if len(case.store) > 1 else 0)

    def put(self, addr, value):
        struct.pack_into("<Q", self.data, addr - HEAP_BASE, value & TOP)

    def blob(self, addr, data):
        self.data[addr - HEAP_BASE:addr - HEAP_BASE + len(data)] = data

    def node(self, shape):
        own, children = shape
        at = self.next
        self.next += NODE_SIZE + 8
        if self.next > HEAP_BASE + USED:
            raise ValueError("tree does not fit the fixture")
        for index, key in enumerate(own):
            self.blob(at + index * VALUE_SIZE, record_bytes(record_of(self.case, key), self.case.tag if key == self.case.token() else None))
            self.put(at + KEYS_AT + 8 * index, key)
            self.where[key] = at + index * VALUE_SIZE
        for index in range(len(own), 11):
            self.put(at + KEYS_AT + 8 * index, 0)  # unused key slots hold zero, so a walk that reads past the length goes on instead of stopping
        struct.pack_into("<H", self.data, at + LEN_AT - HEAP_BASE, len(own))
        for index, child in enumerate(children):
            self.put(at + EDGES_AT + 8 * index, self.node(child))
        return at


# ----- the rule list (written from the block walk; shares no code with the interpreter) -----

def ring_search(keys, token):
    """Ok(index) as (0, index), Err(insertion) as (1, insertion)."""
    low, high = 0, len(keys)
    while low < high:
        mid = (low + high) // 2
        if keys[mid] < token:
            low = mid + 1
        else:
            high = mid
    return (0, low) if low < len(keys) and keys[low] == token else (1, low)


def to_u64(value, m):
    """The f64 to u64 cast the body ends with."""
    if value != value or math.isinf(value):
        return TOP if "nan_max" in m else 0
    if value <= 0:
        if "neg_wrap" in m and value <= -1:
            return int(value) & TOP
        return 0
    if value >= 18446744073709551616.0:
        return (int(value) & TOP) if "over_wrap" in m else TOP
    return int(value + 0.5) if "supply_round" in m else int(value)


def supply_word(rate_word, util_bits, reserve, m):
    if "rate_i64" in m:
        signed = rate_word - (1 << 64) if rate_word >> 63 else rate_word
    elif "rate_u32" in m:
        signed = rate_word & 0xFFFFFFFF
    else:
        signed = i32(rate_word)
    used = to_float(util_bits)
    left = float(signed) * used
    scale = 1e10 if "reserve_e10" in m else 1e14
    share = float(reserve) / (scale if "reserve_plus" in m else -scale) + 1.0
    if "no_reserve" in m:
        share = 1.0
    return to_u64(share * left, m)


def word32(value, m):
    if "little_endian" in m:
        return struct.pack("<Q", value & TOP) + bytes(24)
    return bytes(24) + struct.pack(">Q", value & TOP)


def spec(case, layout, m=frozenset()):
    """Returns (out words or None per word, heap writes, ordered events, divide requests, panicked)."""
    events, writes, div = [], {}, rate.Div(case.faults)
    out = [None] * 5

    def done(panicked=False):
        return out, writes, events, div.log, panicked

    def refuse():
        out[0], out[1] = 0, OUT_OF_GAS
        return done()

    per_byte = 32 if "gas_32" in m else GAS_PER_BYTE
    base = (0 if "gas_base_0" in m else BASE_GAS) + per_byte * case.input_len
    if case.input_len > (MAX_INPUT + 1 if "len_2001" in m else MAX_INPUT) or base > case.gas:
        return refuse()
    events.append(("parse", case.input_len))
    if case.parse[0] != "ok" and not ("parse_any_tag" in m and case.parse[1] != 0):
        events.append(("drop_parse",))
        events.append(("alloc", len(TEXT)))
        if case.fail_alloc == 0:
            events.append(("alloc_error", 1, len(TEXT)))
            return done(True)
        size = 12 if "text_len_12" in m else len(TEXT)
        writes[ALLOCS] = TEXT
        out[0], out[1], out[2], out[3] = 0, size, ALLOCS, size
        return done()
    token = case.token()

    def message(code, extra, second=False):
        if second:
            events.append(("fmt_b", code, extra))
        else:
            events.append(("fmt_a", code, extra, 0))
            events.append(("drop_code",))
        out[0] = 0
        out[1], out[2], out[3] = fmt_words(code, extra)
        return done()

    if (token > case.count) if "count_le" in m else (token >= case.count):
        return message(0xFA, token)
    first, second = (0x0C, 0x00) if "miss_code_swap" in m else (0x00, 0x0C)
    kind = case.store[0]
    if kind == "ring":
        keys = sorted(case.keys)
        answers = list(case.lookups) if case.lookups else [ring_search(keys, token)] * 2
        events.append(("lookup", token))
        if (answers[0][0] & 1) if "ring_bit_first" in m else (answers[0][0] != 0):
            return message(0xF1, first)
        events.append(("lookup", token))
        flag, index = answers[1]
        if (flag != 0) if "ring_full_second" in m else (flag & 1):
            return message(0xF1, second, True)
        if index >= len(keys) and "ring_no_len" not in m:
            return message(0xF1, second, True)
        capacity, head = case.store[1], case.store[2]
        slot = head + index
        if slot >= capacity and "ring_no_wrap" not in m:
            slot -= capacity
        at = STORE + slot * ENTRY_SIZE + 8
    else:
        if kind == "none" or not tree_find(layout.shape, token, case.store[1]):
            return message(0xF1, first)
        at = layout.where[token]
    fields = struct.unpack_from("<4Q", layout.data, at - HEAP_BASE)
    rec = dict(zip(("a", "ia", "b", "ib", "mn", "mx", "kr", "k"), (struct.unpack_from("<Q", layout.data, at - HEAP_BASE + offset)[0]
                                                                  for offset in (0x40, 0x58, 0x60, 0x78, 0x80, 0x88, 0x90, 0x98))))
    borrowed_product, supplied_product = rec["a"] * rec["ia"], rec["b"] * rec["ib"]
    borrowed = div(borrowed_product, E14)
    supplied = div(supplied_product, E14)
    if "ceil_borrow" in m and borrowed_product % E14:
        borrowed += 1
    if case.callee is None:
        rate_word = rate.curve(rec, rate.ratio_or_zero(rec, div), div) // E10
        util = rate.util_result(rec, div)
        util_word = (util[0], util[1] // E10 if not util[0] else util[1])
        util_f64 = None
        if not util[0]:
            again = rate.util_result(rec, div)
            util_f64 = (again[0], to_bits(float(again[1]) / 1e14) if not again[0] else again[1])
    else:
        events.append(("rate",))
        rate_word = case.callee["rate"] & TOP
        events.append(("util_word",))
        util_word = case.callee["util_word"]
        util_f64 = None
        if not util_word[0] & 0xFF == 1:
            events.append(("util_f64",))
            util_f64 = case.callee["util_f64"]
    if util_word[0] & 0xFF == 1 or util_f64[0] & 0xFF == 1:
        if "util_error_ok" not in m:
            return message(0xF1, second, True)
        util_f64 = util_f64 or (0, 0)
    used_bits = to_bits(float(util_word[1])) if "util_word_f64" in m else util_f64[1]
    supply = supply_word(rate_word, used_bits, case.reserve, m)
    tag, opt, f10, f18 = fields
    if "opt_always" in m or ((tag & 0xFFFFFFFF) == 1 if "opt_tag_any" not in m else tag != 0):
        opt_word = opt if "opt_raw" in m else opt // E10
    else:
        opt_word = 0
    if "swap_10_18" in m:
        f10, f18 = f18, f10

    def guarded(product, quotient):
        if "no_total_guard" in m:
            return quotient & TOP
        limit = E14 if "guard_ge" in m else E14 - 1
        return 0 if (product >> 64) > limit else quotient & TOP

    supplied_word, borrowed_word = guarded(supplied_product, supplied), guarded(borrowed_product, borrowed)
    if "swap_totals" in m:
        supplied_word, borrowed_word = borrowed_word, supplied_word
    words = [rate_word, supply, f18, util_word[1], f10, opt_word, supplied_word, borrowed_word]
    if "word_order" in m:
        words[2], words[4] = words[4], words[2]
        words[0], words[3] = words[3], words[0]
    reply = b"".join(word32(word, m) for word in words)
    events.append(("alloc", REPLY_SIZE))
    if case.fail_alloc == 0:
        events.append(("alloc_error", 1, REPLY_SIZE))
        return done(True)
    events.append(("alloc", BOX_SIZE))
    if case.fail_alloc == 1:
        events.append(("alloc_error", 8, BOX_SIZE))
        return done(True)
    writes[ALLOCS] = reply
    writes[ALLOCS + 0x200] = struct.pack("<Q", REPLY_SIZE)
    made = [("free", 1, BOX_SIZE, 0), ("bytes", REPLY_SIZE, 0, REPLY_SIZE)]
    events.extend(reversed(made) if "box_free_first" in m else made)
    extra = per_byte * case.reply_len
    if "gas_no_reply" in m:
        extra = 0
    if extra > TOP:
        extra = TOP
    total = base + extra
    if total > TOP:
        total = total & TOP if "gas_wrap" in m else TOP
    if total > case.gas:
        events.append(("bytes_drop", case.reply_len))
        return refuse()
    out[0], out[1], out[2], out[3], out[4] = VTABLE, ALLOCS, case.reply_len & TOP, DATA_WORD, total
    return done()


# ----- the bytes -----

class ReplyMachine(Machine):
    """The shared interpreter plus the two forms this body needs and the shared module does not model."""

    def step(self, row):
        if row.op == "mul" and row.width == 8:
            # one-operand multiply: carry and overflow are set when the high half is not zero (read by the jo at 0x38e6bd3)
            pc = super().step(row)
            self.cf = self.of = self.regs[RDX] != 0
            self.unsupported_flags.difference_update(("cf", "of"))
            self.unsupported_flags.update(("zf", "sf", "pf"))
            return pc
        return super().step(row)

    def step_vector(self, row, op):
        if op == "cvtsi2sd" and not self.encoding_rex(row) & 8:
            # 32 bit signed source (0x38e687b)
            self.set_low(row.a[1], to_bits(float(i32(self.get(row.b, 4)))))
            return
        super().step_vector(row, op)


class Harness:
    def __init__(self, image, patches=None, stub_callees=False):
        self.image = image
        self.stub_callees = stub_callees
        machine = ReplyMachine(image, patches)
        self.machine = machine
        statics = machine.memory.statics
        for slot, hook in ((SLOT_ALLOC, self.on_alloc), (SLOT_FREE, self.on_free), (SLOT_ALLOC_ERR, self.on_alloc_error),
                           (SLOT_BYTES, self.on_bytes), (SLOT_DIV, self.on_div), (SLOT_FMT_B, self.on_fmt_b)):
            statics[slot] = MARK_BASE + slot
            machine.slots[MARK_BASE + slot] = hook
        machine.slots[MARK_DROP] = self.on_bytes_drop
        machine.calls.update({PARSE: self.on_parse, DROP_PARSE: self.on_drop_parse, FMT_A: self.on_fmt_a, DROP_CODE: self.on_drop_code,
                              LOOKUP: self.on_lookup})
        if stub_callees:
            machine.calls.update({RATE: self.on_rate, UTIL_WORD: self.on_util_word})
            statics[SLOT_UTIL_F64] = MARK_BASE + SLOT_UTIL_F64
            machine.slots[MARK_BASE + SLOT_UTIL_F64] = self.on_util_f64
        else:
            machine.real = frozenset((RATE, UTIL_WORD, UTIL_F64))
            statics[SLOT_UTIL_F64] = UTIL_F64
        self.case = self.layout = None
        self.events, self.divides = [], []

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def read(self, addr):
        return self.machine.memory.read(addr, 8)

    def on_div(self, machine):
        regs = machine.regs
        num, den = regs[RDI] | regs[RSI] << 64, regs[RDX] | regs[RCX] << 64
        index = len(self.divides)
        self.divides.append((num, den))
        if index in self.case.faults:
            q = self.case.faults[index]
        else:
            self.expect(den != 0, "divide by zero")
            q = num // den
        regs[RAX], regs[RDX] = q & TOP, (q >> 64) & TOP
        machine.keep_rdx = True

    def on_parse(self, machine):
        regs = machine.regs
        self.expect(regs[RSI] == INPUT and regs[RDX] == self.case.input_len, "parser arguments")
        self.events.append(("parse", regs[RDX]))
        block = bytearray((0x40 + index) & 0xFF for index in range(0x58))
        if self.case.parse[0] == "ok":
            block[0] = 0x0C
            struct.pack_into("<Q", block, 8, self.case.parse[1])
        else:
            block[0] = self.case.parse[1]
        self.parsed = bytes(block)
        machine.memory.put_bytes(regs[RDI], self.parsed)
        self.parse_at = regs[RDI]

    def on_drop_parse(self, machine):
        self.expect(machine.memory.bytes_at(machine.regs[RDI], 0x58) == self.parsed, "the refused parse result is passed on whole")
        self.events.append(("drop_parse",))

    def on_alloc(self, machine):
        size = machine.regs[RDI]
        index = self.allocs
        self.allocs += 1
        self.events.append(("alloc", size))
        machine.regs[RAX] = 0 if self.case.fail_alloc == index else ALLOCS + 0x200 * index
        self.expect(size <= 0x200, "allocation fits the fixture")

    def on_alloc_error(self, machine):
        self.events.append(("alloc_error", machine.regs[RDI], machine.regs[RSI]))
        raise Panicked("allocation failure")

    def on_free(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] >= ALLOCS and (regs[RDI] - ALLOCS) % 0x200 == 0, "free of an allocation")
        self.events.append(("free", (regs[RDI] - ALLOCS) // 0x200, regs[RSI], regs[RDX]))

    def code_at(self, addr):
        memory = self.machine.memory
        code = memory.read(addr, 2)
        return code, (memory.read(addr + 8, 8) if code == 0xFA else memory.read(addr + 2, 1))

    def on_fmt_a(self, machine):
        regs = machine.regs
        code, extra = self.code_at(regs[RSI])
        self.events.append(("fmt_a", code, extra, regs[RDX] & 0xFFFFFFFF))
        self.code_addr = regs[RSI]
        for index, word in enumerate(fmt_words(code, extra)):
            machine.memory.write(regs[RDI] + 8 * index, 8, word)

    def on_drop_code(self, machine):
        self.expect(machine.regs[RDI] == self.code_addr, "the code that was formatted is dropped")
        self.events.append(("drop_code",))

    def on_fmt_b(self, machine):
        regs = machine.regs
        code, extra = self.code_at(regs[RSI])
        self.events.append(("fmt_b", code, extra))
        for index, word in enumerate(fmt_words(code, extra)):
            machine.memory.write(regs[RDI] + 8 * index, 8, word)

    def on_lookup(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == HOLD_B + 0x58, "search receives the store")
        key = self.read(regs[RSI])
        index = sum(1 for event in self.events if event[0] == "lookup")
        self.events.append(("lookup", key))
        if self.case.lookups:
            flag, where = self.case.lookups[index]
        else:
            flag, where = ring_search(sorted(self.case.keys), key)
        regs[RAX], regs[RDX] = flag & TOP, where & TOP
        machine.keep_rdx = True

    def on_bytes(self, machine):
        regs = machine.regs
        cap, ptr, size = (self.read(regs[RSI] + 8 * index) for index in range(3))
        self.expect(ptr == ALLOCS, "reply buffer")
        self.events.append(("bytes", cap, (ptr - ALLOCS) // 0x200, size))
        for index, word in enumerate((VTABLE, ptr, self.case.reply_len, DATA_WORD)):
            machine.memory.write(regs[RDI] + 8 * index, 8, word)

    def on_bytes_drop(self, machine):
        regs = machine.regs
        self.expect(self.read(regs[RDI]) == DATA_WORD and regs[RSI] == ALLOCS, "reply drop arguments")
        self.events.append(("bytes_drop", regs[RDX]))

    def subject(self, addr):
        self.expect(addr == self.subject_at, "callee receives the found record")

    def on_rate(self, machine):
        self.subject(machine.regs[RDI])
        self.events.append(("rate",))
        machine.regs[RAX] = self.case.callee["rate"] & TOP

    def result(self, machine, answer):
        self.subject(machine.regs[RSI])
        memory = machine.memory
        memory.put_bytes(machine.regs[RDI], bytes((0x70 + index) & 0xFF for index in range(0x10)))
        memory.write(machine.regs[RDI], 1, answer[0])
        if answer[0] & 0xFF == 1:
            memory.write(machine.regs[RDI] + 1, 1, answer[1])
        else:
            memory.write(machine.regs[RDI] + 8, 8, answer[1])

    def on_util_word(self, machine):
        self.events.append(("util_word",))
        self.result(machine, self.case.callee["util_word"])

    def on_util_f64(self, machine):
        self.events.append(("util_f64",))
        self.result(machine, self.case.callee["util_f64"])

    def run(self, case):
        layout = Layout(case)
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        memory.put_bytes(HEAP_BASE, bytes(layout.data))
        machine.xmm = [POISON | POISON << 64] * 16
        self.case, self.layout = case, layout
        self.events, self.divides, self.allocs = [], [], 0
        self.parsed = self.parse_at = self.code_addr = None
        token = case.token() if case.parse[0] == "ok" else None
        self.subject_at = None
        if case.store[0] == "ring" and token is not None:
            answers = case.lookups or [ring_search(sorted(case.keys), token)] * 2
            slot = case.store[2] + answers[1][1]
            self.subject_at = STORE + (slot - case.store[1] if slot >= case.store[1] else slot) * ENTRY_SIZE + 8
        elif token is not None:
            self.subject_at = layout.where.get(token)
        before = bytes(layout.data)
        panicked = False
        try:
            value = machine.run(ENTRY, {RDI: OUT, RSI: CTX, RDX: INPUT, RCX: case.input_len, R8: case.gas})
            if value != OUT:
                raise Halt("result pointer")
        except Panicked:
            panicked = True
        return layout, before, bytes(memory.heap[:USED]), list(self.events), list(self.divides), panicked


def expected_heap(before, out, writes):
    data = bytearray(before)
    for index, word in enumerate(out):
        if word is not None:
            struct.pack_into("<Q", data, OUT - HEAP_BASE + 8 * index, word)
    for addr, blob in writes.items():
        data[addr - HEAP_BASE:addr - HEAP_BASE + len(blob)] = blob
    return bytes(data)


def compare(harness, case, m=frozenset()):
    """None when the bytes and the rule list agree on every heap byte, every event, every divide and the panic; else the first difference."""
    layout, before, after, events, divides, panicked = harness.run(case)
    out, writes, want_events, want_divides, want_panic = spec(case, layout, m)
    if panicked != want_panic:
        return "panic"
    if events != want_events:
        return "events %r against %r" % (events, want_events)
    if divides != want_divides:
        return "divide requests"
    if not panicked and after != expected_heap(before, out, writes):
        return "heap bytes"
    return None


def digest_row(harness, case):
    layout, before, after, events, divides, panicked = harness.run(case)
    words = struct.unpack_from("<5Q", after, OUT - HEAP_BASE)
    if panicked:
        form = "panic"
    elif words[0] == 0:
        form = "out of gas" if words[1] == OUT_OF_GAS else "message"
    else:
        form = "reply"
    reply = after[ALLOCS - HEAP_BASE:ALLOCS - HEAP_BASE + REPLY_SIZE] if form == "reply" else b""
    return (case.name, "stub" if harness.stub_callees else "real", form, words[4] if form == "reply" else "-",
            hashlib.sha256(after).hexdigest()[:16], reply.hex() if reply else "-", len(divides), " ".join(event[0] for event in events))


# ----- cases -----

def named_cases():
    """(case, needs stubbed callees) pairs."""
    rows = []

    def add(name, stub=False, **fields):
        rows.append((Case(name, **fields), stub))

    reply_gas = GAS_PER_BYTE * REPLY_SIZE
    for size in (0, 1, 31, 32, 33, 1999, 2000, 2001, 2002, 4000, 1 << 32, 1 << 63, TOP):
        add("input length %d" % size, input_len=size)
    for size in (0, 32, 2000):
        base = BASE_GAS + GAS_PER_BYTE * size
        for label, gas in (("zero", 0), ("one below the first charge", base - 1), ("exactly the first charge", base), ("one above the first charge", base + 1),
                           ("one below the whole charge", base + reply_gas - 1), ("exactly the whole charge", base + reply_gas),
                           ("one above the whole charge", base + reply_gas + 1), ("the largest word", TOP)):
            add("gas %s, input length %d" % (label, size), input_len=size, gas=gas)
    add("first charge is 32 a byte short", input_len=2000, gas=BASE_GAS + 32 * 2000 + reply_gas)
    for tag in (0, 1, 0x0B, 0x0D, 0x8C, 0xFF):
        add("parse refused with tag %#x" % (tag & 0xFF), parse=("err", tag & 0xFF))
    add("parse refused, text allocation fails", parse=("err", 3), fail_alloc=0)
    add("parse refused at the smallest gas", parse=("err", 3), gas=BASE_GAS + GAS_PER_BYTE * 32)
    for token, count in ((0, 0), (0, 1), (7, 7), (7, 8), (8, 7), (TOP, TOP), (TOP - 1, TOP), (5, TOP)):
        add("token %d against count %d" % (token, count), parse=("ok", token), count=count, keys=[token], store=("tree", 0, 3))
    add("empty store", store=("none",))
    add("empty store with a height", store=("none", 3))
    spread = [3, 7, 11, 19, 23, 31, 43, 47, 59, 61, 71, 79, 83, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163]
    for height, separators, keys in ((0, 3, spread[:1]), (0, 3, spread[:2]), (0, 3, spread[:11]), (1, 1, spread[:3]), (1, 3, spread[:15]),
                                     (1, 11, spread[:27]), (2, 2, spread[:26]), (2, 3, spread[:27]), (1, 2, []), (2, 1, spread[:1])):
        label = "tree height %d, %d separators, %d keys" % (height, separators, len(keys))
        for token in sorted(set(keys[:1] + keys[-1:] + keys[len(keys) // 2:len(keys) // 2 + 1] + keys[1:2])):
            add("%s, token %d found" % (label, token), parse=("ok", token), keys=keys, store=("tree", height, separators), count=1000)
        probes = [0, 1000] + ([keys[0] + 1, keys[-1] - 1] if len(keys) > 2 else []) + ([keys[len(keys) // 2] + 1] if keys else [])
        for token in sorted(set(probes) - set(keys)):
            add("%s, token %d missing" % (label, token), parse=("ok", token), keys=keys, store=("tree", height, separators), count=2000)
    for token in spread[:27]:
        add("tree height 2, every key, token %d" % token, parse=("ok", token), keys=spread[:27], store=("tree", 2, 2), count=1000)
    ring = [5, 9, 14, 20, 33, 41]
    for capacity, head in ((6, 0), (6, 5), (8, 3), (8, 7), (16, 0), (7, 6)):
        for token in ring:
            add("ring capacity %d head %d, token %d found" % (capacity, head, token), parse=("ok", token), keys=ring, store=("ring", capacity, head))
        for token in (0, 6, 21, 99):
            add("ring capacity %d head %d, token %d missing" % (capacity, head, token), parse=("ok", token), keys=ring, store=("ring", capacity, head))
    add("ring empty", parse=("ok", 5), keys=[], store=("ring", 4, 2))
    answers = (("first search answers 1", [(1, 2), (0, 2)]), ("first search answers 2", [(2, 2), (0, 2)]), ("first search answers 2^32", [(1 << 32, 2), (0, 2)]),
               ("second search answers 1", [(0, 2), (1, 2)]), ("second search answers 2", [(0, 2), (2, 2)]), ("second search answers 3", [(0, 2), (3, 2)]),
               ("second search answers 0x100", [(0, 2), (0x100, 2)]), ("second index at the length", [(0, 2), (0, 6)]),
               ("second index past the length", [(0, 2), (0, 7)]), ("second index is the last", [(0, 2), (0, 5)]),
               ("second index differs from the first", [(0, 1), (0, 4)]), ("second index is huge", [(0, 2), (0, TOP)]))
    for label, lookups in answers:
        token = ring[lookups[1][1]] if lookups[1][1] < len(ring) else 14
        add("ring, %s" % label, parse=("ok", token), keys=ring, store=("ring", 8, 5), lookups=lookups)
    for name, rec, faults in rate.base_records():
        add("record: %s" % name, rec=rec, faults={index + 2: value for index, value in faults.items()})
    for name, faults in (("borrowed quotient injected", {0: 12345}), ("supplied quotient injected", {1: 54321}), ("borrowed quotient with a high word", {0: (1 << 64) | 77}),
                         ("supplied quotient with a high word", {1: (5 << 64) | 99}), ("both quotients injected", {0: TOP, 1: TOP - 1})):
        add("own divide: %s" % name, rec=rate.record(a=50, b=100), faults=faults)
    for reserve in (0, 1, 10 ** 13, 5 * 10 ** 13, E14 - 1, E14, E14 + 1, 2 * E14, 1 << 53, (1 << 53) + 1, 1 << 63, (1 << 63) + 1025, TOP - 1024, TOP):
        add("reserve word %d" % reserve, reserve=reserve, rec=rate.record(a=90, b=100, mn=10 ** 12, kr=10 ** 13, mx=5 * 10 ** 14))
    for name, ltv, tag in (("absent", None, None), ("present", 123456789012345, None), ("present, below 1e10", E10 - 1, None), ("present, exactly 1e10", E10, None),
                           ("present, largest word", TOP, None), ("tag 0", 77 * E10, 0), ("tag 2 with a value", 77 * E10, 2), ("tag 3", 77 * E10, 3),
                           ("tag 1 in the low half only", 77 * E10, (5 << 32) | 1), ("tag 1 in the high half only", 77 * E10, 1 << 32)):
        add("optional word %s" % name, rec=rate.record(a=50, b=100, ltv=ltv, px=0x1122334455667788, bal=0x99AABBCCDDEEFF00), tag=tag)
    for px, bal in ((0, 0), (1, 2), (TOP, 0), (0, TOP), (0x0102030405060708, 0x1112131415161718)):
        add("plain words %#x %#x" % (px, bal), rec=rate.record(a=50, b=100, px=px, bal=bal))
    add("reply allocation fails", fail_alloc=0)
    add("box allocation fails", fail_alloc=1)
    for label, size in (("zero", 0), ("one", 1), ("255", 255), ("257", 257), ("2^58", 1 << 58), ("the largest product that fits", TOP // 33),
                        ("the smallest product that overflows", TOP // 33 + 1), ("2^63", 1 << 63), ("the largest word", TOP)):
        add("reported reply length %s" % label, reply_len=size, gas=TOP)
        add("reported reply length %s, gas one below the largest word" % label, reply_len=size, gas=TOP - 1)
    add("reported reply length 257 at the whole charge of 256", reply_len=257, gas=BASE_GAS + GAS_PER_BYTE * 32 + GAS_PER_BYTE * REPLY_SIZE)

    def stub(name, rate_word=5000, word=(0, 1234), f64=(0, to_bits(0.5)), **fields):
        add("callee: %s" % name, True, callee=dict(rate=rate_word, util_word=word, util_f64=f64), **fields)

    for value in (0, 1, 1844674407, (1 << 31) - 1, 1 << 31, (1 << 31) + 1, (1 << 32) - 1, 1 << 32, (1 << 32) + 5, (7 << 32) | 0x80000003, 1 << 63, TOP):
        stub("rate word %#x" % value, rate_word=value, f64=(0, to_bits(1.0)), reserve=0)
        stub("rate word %#x with a negative share" % value, rate_word=value, f64=(0, to_bits(1.0)), reserve=3 * E14)
    for label, used in (("0", 0.0), ("-0", -0.0), ("1", 1.0), ("0.5", 0.5), ("0.1", 0.1), ("-1", -1.0), ("1e-320", 1e-320), ("1e10", 1e10), ("8.6e9", 8.6e9),
                        ("1e300", 1e300), ("-1e300", -1e300), ("inf", math.inf), ("-inf", -math.inf), ("nan", math.nan), ("2^64 over the rate", 18446744073709551616.0 / 4096),
                        ("just below 2^64 over the rate", 18446744073709549568.0 / 4096), ("2^63 over the rate", 9223372036854775808.0 / 4096),
                        ("just below 2^63 over the rate", 9223372036854774784.0 / 4096), ("just above 2^63 over the rate", 9223372036854777856.0 / 4096)):
        for reserve in (0, 5 * 10 ** 13, 2 * E14):
            stub("utilization %s, reserve %d" % (label, reserve), rate_word=4096, f64=(0, to_bits(used)), reserve=reserve)
    stub("utilization nan with a payload", rate_word=4096, f64=(0, 0x7FF4000000001234), reserve=0)
    stub("product is the largest finite f64", rate_word=1, f64=(0, 0x7FEFFFFFFFFFFFFF), reserve=0)
    stub("product is the most negative finite f64", rate_word=0xFFFFFFFF, f64=(0, 0x7FEFFFFFFFFFFFFF), reserve=0)
    stub("product is one step below the largest finite f64", rate_word=1, f64=(0, 0x7FEFFFFFFFFFFFFE), reserve=0)
    stub("utilization 0.3 with rate 7", rate_word=7, f64=(0, to_bits(0.3)), reserve=0)
    stub("utilization 0.7 with rate 10", rate_word=10, f64=(0, to_bits(0.7)), reserve=0)
    stub("utilization 0.999 with rate 1000", rate_word=1000, f64=(0, to_bits(0.9995)), reserve=0)
    stub("utilization 0.5 with rate 3", rate_word=3, f64=(0, to_bits(0.5)), reserve=0)
    for code in (0, 2, 3, 0xFF):
        stub("word utilization refuses with %d" % code, word=(1, code))
        stub("f64 utilization refuses with %d" % code, f64=(1, code))
    for tag in (0, 2, 0x100, 0x101, 0xFF):
        stub("word utilization tag %#x" % tag, word=(tag, 4321))
        stub("f64 utilization tag %#x" % tag, f64=(tag, to_bits(0.25)))
    stub("utilization words differ", word=(0, TOP), f64=(0, to_bits(0.125)))
    for label, rec in (("supplied product one below the guard", rate.record(a=5, b=rate.EDGE_LEFT, ib=rate.EDGE_RIGHT)),
                       ("supplied product at the guard", rate.record(a=5, b=1 << 63, ib=2 * E14)),
                       ("supplied product past the guard", rate.record(a=5, b=TOP, ib=TOP)),
                       ("borrowed product one below the guard", rate.record(a=rate.EDGE_LEFT, ia=rate.EDGE_RIGHT, b=9)),
                       ("borrowed product at the guard", rate.record(a=1 << 63, ia=2 * E14, b=9)),
                       ("borrowed product past the guard", rate.record(a=TOP, ia=TOP, b=9)),
                       ("both products past the guard", rate.record(a=TOP, ia=TOP, b=TOP, ib=TOP)),
                       ("borrowed high word exactly 1e14, quotient low word 2", rate.record(a=(1 << 63) + 1, ia=2 * E14, b=9)),
                       ("supplied high word exactly 1e14, quotient low word 2", rate.record(a=5, b=(1 << 63) + 1, ib=2 * E14)),
                       ("borrowed high word 1e14 - 1, quotient the largest word", rate.record(a=TOP, ia=E14, b=9)),
                       ("borrowed total needs the ceil", rate.record(a=3, ia=E14 + 1, b=1000000)),
                       ("zero shares", rate.record(a=0, ia=0, b=0, ib=0))):
        stub("totals: %s" % label, rec=rec)
    stub("reply allocation fails", fail_alloc=0)
    stub("box allocation fails", fail_alloc=1)
    stub("out of gas after the reply", gas=BASE_GAS + GAS_PER_BYTE * 32 + GAS_PER_BYTE * REPLY_SIZE - 1)
    return rows


def lcg(seed):
    state = seed & TOP
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & TOP
        yield state >> 11


def draw(stream):
    kind = next(stream) % 8
    value = next(stream) | next(stream) << 53
    if kind == 0:
        return value & TOP
    if kind == 1:
        return value % 1000
    if kind == 2:
        return E14 + (value % 2001) - 1000
    if kind == 3:
        return 1 << (value % 64)
    if kind == 4:
        return value % (1 << 40)
    if kind == 5:
        return (value % 200) * 10 ** 12
    if kind == 6:
        return TOP - value % 1000
    return value % (2 * E14)


def vector_cases(count, seed=0x5EED0812):
    """(case, needs stubbed callees) pairs drawn from one stream."""
    stream = lcg(seed)
    for number in range(count):
        choice = next(stream) % 100
        size = next(stream) % 2100 if choice < 6 else next(stream) % 400
        gas = TOP if choice >= 12 else BASE_GAS + GAS_PER_BYTE * size + next(stream) % (2 * GAS_PER_BYTE * REPLY_SIZE)
        amount = 1 + next(stream) % 27
        keys = sorted({1 + next(stream) % 5000 for _ in range(amount)})
        present = next(stream) % 10 != 0
        token = keys[next(stream) % len(keys)] if present else next(stream) % 5001
        fields = dict(input_len=size, gas=gas, parse=("ok", token), keys=keys, count=5001 if next(stream) % 20 else token + next(stream) % 2)
        if choice in (12, 13):
            fields["parse"] = ("err", next(stream) % 256)
            if fields["parse"][1] == 0x0C:
                fields["parse"] = ("err", 0x0D)
        if next(stream) % 2:
            capacity = len(keys) + next(stream) % 5
            fields["store"] = ("ring", capacity, next(stream) % capacity)
        else:
            height = next(stream) % 3
            if height == 0:
                keys = keys[:11]
                fields["keys"] = keys
                if fields["parse"][0] == "ok" and present:
                    fields["parse"] = ("ok", keys[next(stream) % len(keys)])
            separators = 1 + next(stream) % 4
            if height == 1 and len(keys) > 23:
                separators = max(separators, 2)  # keep every leaf within 11 keys
            fields["store"] = ("tree", height, separators)
        a_small = next(stream) % 3
        rec = rate.record(a=draw(stream) % 10 ** 12 if a_small else draw(stream), b=1 + draw(stream) % 10 ** 13 if a_small else draw(stream),
                          ia=E14 + next(stream) % 10 ** 13 if a_small else draw(stream), ib=E14 + next(stream) % 10 ** 13 if a_small else draw(stream),
                          mn=draw(stream) % (3 * 10 ** 13), kr=draw(stream) % (9 * 10 ** 13), mx=draw(stream) % (4 * E14), k=draw(stream) % (E14 + 2),
                          ltv=draw(stream) if next(stream) % 2 else None, px=draw(stream), bal=draw(stream))
        fields["rec"] = rec
        fields["reserve"] = draw(stream) if next(stream) % 4 == 0 else draw(stream) % (E14 + 1)
        stubbed = next(stream) % 3 == 0
        if stubbed:
            pick = next(stream) % 6
            used = (to_bits((next(stream) % 10 ** 6) / 10 ** 6), to_bits(float(draw(stream))), draw(stream), to_bits(-float(draw(stream) % 1000)),
                    to_bits(float(draw(stream)) * 1e280), to_bits((next(stream) % 4096) / 4096.0))[pick]
            fields["callee"] = dict(rate=draw(stream) if next(stream) % 2 else next(stream) % (1 << 31),
                                    util_word=(1 if next(stream) % 25 == 0 else next(stream) % 2 * 2, draw(stream)),
                                    util_f64=(1 if next(stream) % 25 == 0 else 0, used))
            if fields["callee"]["util_word"][0] == 1:
                fields["callee"]["util_word"] = (1, next(stream) % 4)
            if fields["callee"]["util_f64"][0] == 1:
                fields["callee"]["util_f64"] = (1, next(stream) % 4)
        yield Case("vector %d" % number, **fields), stubbed


# ----- controls -----

def first_failure(harnesses, cases, variant=frozenset()):
    """The first case the bytes and the rule list disagree on, or None."""
    for case, stubbed in cases:
        try:
            if compare(harnesses[stubbed], case, variant) is not None:
                return case
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, ZeroDivisionError, struct.error, TypeError):
            return case
    return None


WALK_TWO = "the second walk repeats a search the first walk already won on the same tree, so its height counter is never the reason to stop"
CAST = "the clamp block and the cast after it give the same word: the cast alone already returns 0 below zero and the largest word above 2^64"
EQUIVALENT = {
    (0x38E6665, "immediate"): "the edited byte is text byte 5, which the head store at +0..+7 writes again",
    (0x38E6746, "displacement"): WALK_TWO,
    (0x38E67A5, "immediate"): WALK_TWO,
    (0x38E68C3, "immediate"): "bit 0 of the sign mask: no value changes side of the 0x7fefffffffffffff test when bit 0 is cleared",
    (0x38E68F3, "condition"): CAST,
    (0x38E6901, "condition"): CAST,
    (0x38E69B4, "immediate"): "shift 62 for 63 differs only in bit 0 of the second conversion, and every f64 from 2^62 up is a multiple of 1024",
    (0x38E6C35, "immediate"): "the saturated product (2^64-1 or 2^64-2) plus a first charge of at least 1000 carries either way",
}


def run_mutants(image, rows, seen, cases):
    results = []
    plain = [pair for pair in cases if not pair[1]]
    forced = [pair for pair in cases if pair[1]]
    for va, kind, patch in rate.edits_for(image, rows, seen):
        harnesses = {False: Harness(image, patch), True: Harness(image, patch, stub_callees=True)}
        for harness in harnesses.values():
            harness.machine.step_limit = 60000
        if first_failure(harnesses, plain) is not None:
            results.append((va, kind, "killed", "real callees"))
        elif first_failure(harnesses, forced) is not None:
            results.append((va, kind, "killed", "injected callee answers only"))
        else:
            results.append((va, kind, "survived", EQUIVALENT.get((va, kind), "UNEXPLAINED")))
    return results


def structural_controls(image, harnesses, cases):
    rows = []
    blob = bytearray(image.blob)
    blob[1000] ^= 1
    rows.append(("one flipped file byte changes the SHA-256", "detected" if hashlib.sha256(bytes(blob)).hexdigest() != SHA256 else "MISSED"))
    for label, va in (("address inside the body", ENTRY + 1), ("address before the body", ENTRY - 1), ("the first landing pad", BODY_END),
                      ("address in .rodata", 0x459090), ("address past the file", 0x7FFFFFFFFF)):
        try:
            image.exact_fde(va)
            rows.append((label + " is refused as a function start", "MISSED"))
        except EvidenceError:
            rows.append((label + " is refused as a function start", "detected"))
    relative = image.relative()
    rows.append(("table slot of the neighbour entry does not hold the body", "detected" if relative.get(TABLE_SLOT - 0x20) != ENTRY else "MISSED"))
    rows.append(("f64 utilization slot is not the word utilization", "detected" if relative.get(SLOT_UTIL_F64) != UTIL_WORD else "MISSED"))
    probe = next(case for case, stubbed in cases if case.name == "record: half used")
    layout, before, after, events, divides, panicked = harnesses[False].run(probe)
    other = Case("other reserve", rec=probe.rec, reserve=probe.reserve + E14 // 2)
    out, writes, _, _, _ = spec(other, Layout(other))
    rows.append(("reply of one reserve word compared with the rule for another", "detected" if after != expected_heap(before, out, writes) else "MISSED"))
    damaged = bytearray(after)
    damaged[ALLOCS - HEAP_BASE + 0x3F] ^= 1
    out, writes, _, _, _ = spec(probe, layout)
    rows.append(("one flipped reply bit", "detected" if bytes(damaged) != expected_heap(before, out, writes) else "MISSED"))
    damaged = bytearray(after)
    damaged[STORE - HEAP_BASE + 0x40] ^= 1
    rows.append(("one flipped store bit after the run", "detected" if bytes(damaged) != expected_heap(before, out, writes) else "MISSED"))
    return rows


def table_rows(image):
    relative = image.relative()
    if relative.get(TABLE_SLOT) != ENTRY:
        raise EvidenceError("table slot does not hold the body")
    rows = []
    for slot in (TABLE_SLOT - 0x20, TABLE_SLOT, TABLE_SLOT + 0x20):
        address = bytes(image.blob[image.offset(slot - 0x18):image.offset(slot - 0x18) + 20])
        rows.append(("%#x" % slot, address.hex(), "%#x" % relative[slot]))
    if rows[1][1] != "00" * 18 + "0812":
        raise EvidenceError("table address bytes")
    return rows


def slot_rows(image):
    relative = image.relative()
    rows = []
    for slot, target in sorted(SLOT_TARGETS.items()):
        if relative.get(slot) != target:
            raise EvidenceError("slot does not hold the target: %#x" % slot)
        rows.append(("%#x" % slot, "%#x" % target))
    return rows


def site_rows(rows):
    sites = []
    for row in rows:
        if row.op == "call":
            sites.append(("%#x" % row.va, "direct", "%#x" % row.target))
        elif row.op == "calli":
            operand = row.a
            if operand[1] is None and operand[2] is None and row.rip_at is not None:
                sites.append(("%#x" % row.va, "slot", "%#x" % operand[4]))
            else:
                sites.append(("%#x" % row.va, "register memory", "-"))
    return sites


def constant_rows(image, rows):
    out, seen = [], set()
    for row in rows:
        for operand in (row.a, row.b):
            if operand and operand[0] == "m" and row.rip_at is not None and operand[1] is None and operand[2] is None and row.op != "calli":
                va = operand[4]
                if va in seen:
                    continue
                seen.add(va)
                if va not in CONSTANTS:
                    raise EvidenceError("unlisted constant %#x" % va)
                data = bytes(image.blob[image.offset(va):image.offset(va) + (16 if va in (0x451210, 0x450170) else 8)])
                value = "-" if len(data) == 16 else repr(to_float(struct.unpack("<Q", data)[0]))
                out.append(("%#x" % row.va, "rip %#x" % va, CONSTANTS[va], value, data.hex()))
        if row.op == "mov" and row.size >= 10 and row.data[0] & 0xF8 == 0x48 and 0xB8 <= row.data[1] <= 0xBF:
            value = struct.unpack_from("<Q", row.data, 2)[0]
            out.append(("%#x" % row.va, "movabs", "-", str(value), "%#x" % value))
    return out


def reciprocal_row():
    spare = MUL_E10 * E10 - (1 << 97)
    worst = TOP * spare
    if spare <= 0 or worst >= 1 << 97:
        raise EvidenceError("reciprocal bound fails")
    return [("optional word / 1e10", "%#x" % MUL_E10, 97, spare, 1 << 64, worst, 1 << 97)]


def sample_rows(harness):
    rows = []
    for label, rec, reserve in (("half used, reserve 10%", rate.record(a=50, b=100, mn=0, kr=5 * 10 ** 12, mx=E14, k=8 * 10 ** 13, ltv=8 * 10 ** 13, px=3, bal=4), 10 ** 13),
                                ("90% used, reserve 10%", rate.record(a=90, b=100), 10 ** 13), ("90% used, reserve 0", rate.record(a=90, b=100), 0),
                                ("90% used, reserve 100%", rate.record(a=90, b=100), E14), ("fully used, reserve 25%", rate.record(a=100, b=100), 25 * 10 ** 12),
                                ("empty market", rate.record(), 10 ** 13)):
        case = Case(label, rec=rec, reserve=reserve)
        layout, before, after, events, divides, panicked = harness.run(case)
        reply = after[ALLOCS - HEAP_BASE:ALLOCS - HEAP_BASE + REPLY_SIZE]
        words = [int.from_bytes(reply[index * 32:index * 32 + 32], "big") for index in range(8)]
        rows.append((label, reserve) + tuple(words))
    return rows


def rust_vectors(harnesses, count=600):
    """Inputs and the reply words the bytes gave, for the Rust tests: token-found cases with real callees only."""
    rows = []
    pool = [pair for pair in named_cases() if not pair[1] and pair[0].name.startswith(("record:", "reserve word", "optional word", "plain words"))]
    pool += [pair for pair in vector_cases(count) if not pair[1]]
    for case, _ in pool:
        if case.faults or case.parse[0] != "ok":
            continue
        layout, before, after, events, divides, panicked = harnesses[False].run(case)
        at = harnesses[False].subject_at
        kinds = {event[0] for event in events}
        if panicked or at is None or "fmt_a" in kinds or not kinds & {"bytes", "fmt_b"}:
            continue
        fields = [struct.unpack_from("<Q", before, at - HEAP_BASE)[0] & 0xFFFFFFFF]
        fields += [struct.unpack_from("<Q", before, at - HEAP_BASE + offset)[0] for offset in (8, 0x10, 0x18, 0x40, 0x58, 0x60, 0x78, 0x80, 0x88, 0x90, 0x98)]
        if "fmt_b" in kinds:
            result = ["refused"]
        else:
            reply = after[ALLOCS - HEAP_BASE:ALLOCS - HEAP_BASE + REPLY_SIZE]
            result = [str(int.from_bytes(reply[index * 32:index * 32 + 32], "big")) for index in range(8)]
        rows.append([str(value) for value in fields] + [str(case.reserve)] + result)
    return rows


def analyse(image, vectors=9000, mutate=True):
    harnesses = {False: Harness(image), True: Harness(image, stub_callees=True)}
    cases = named_cases()
    names = [case.name for case, _ in cases]
    if len(set(names)) != len(names):
        raise EvidenceError("duplicate case name")
    outcomes = []
    for case, stubbed in cases:
        difference = compare(harnesses[stubbed], case)
        if difference:
            raise EvidenceError("case disagrees with the rule list: %s: %s" % (case.name, difference))
        outcomes.append(digest_row(harnesses[stubbed], case))
    vector_rows, vector_count, stub_count = [], 0, 0
    for case, stubbed in vector_cases(vectors):
        difference = compare(harnesses[stubbed], case)
        if difference:
            raise EvidenceError("vector disagrees with the rule list: %s: %s" % (case.name, difference))
        if vector_count % 10 == 0:
            vector_rows.append(digest_row(harnesses[stubbed], case))
        vector_count += 1
        stub_count += stubbed
    rows = decode_range(image, ENTRY, BODY_END)
    seen_real, seen_any = set(harnesses[False].machine.seen), set(harnesses[False].machine.seen) | set(harnesses[True].machine.seen)
    body = [row for row in rows if row.op not in ("int3", "nop")]
    unreached = [row.va for row in body if row.va not in seen_any]
    stub_only = [row.va for row in body if row.va in seen_any and row.va not in seen_real]
    sample = cases + list(vector_cases(400, seed=0x77))
    variants = []
    for name in VARIANTS:
        failure = first_failure(harnesses, sample, frozenset((name,)))
        variants.append((name, "detected" if failure is not None else "MISSED", failure.name if failure else "-"))
    result = dict(rows=rows, cases=cases, outcomes=outcomes, vector_rows=vector_rows, vector_count=vector_count, stub_count=stub_count, unreached=unreached,
                  stub_only=stub_only, variants=variants, structural=structural_controls(image, harnesses, cases), table=table_rows(image), slots=slot_rows(image),
                  sites=site_rows(rows), constants=constant_rows(image, rows), reciprocal=reciprocal_row(), samples=sample_rows(harnesses[False]),
                  rust=rust_vectors(harnesses), fde=image.exact_fde(ENTRY))
    if mutate:
        kill = cases + list(vector_cases(60, seed=0x99))
        result["mutations"] = run_mutants(image, rows, seen_any, kill)
        unexplained = [row for row in result["mutations"] if row[3] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(hex(row[0]), row[1]) for row in unexplained])
    return result


def render(result):
    files = {}

    def tsv(name, header, rows):
        files[name] = "\n".join(["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]) + "\n"

    rows = result["rows"]
    tsv("function-rows.tsv", ("address", "size", "bytes", "operation"), [("%#x" % row.va, row.size, row.data.hex(), row.op) for row in rows])
    tsv("table-entries.tsv", ("slot", "address_bytes", "callback"), result["table"])
    tsv("slots.tsv", ("slot", "relative_target"), result["slots"])
    tsv("call-sites.tsv", ("site", "form", "target_or_slot"), result["sites"])
    tsv("constants.tsv", ("row", "form", "role", "value", "bits"), result["constants"])
    tsv("reciprocals.tsv", ("divide", "multiplier", "shift", "spare", "inputs_below", "worst_error", "two_to_shift"), result["reciprocal"])
    tsv("reply-samples.tsv", ("case", "reserve_word", "word0_rate", "word1_supply_rate", "word2_plus_0x18", "word3_utilization", "word4_plus_0x10",
                              "word5_optional", "word6_supplied", "word7_borrowed"), result["samples"])
    header = ("case", "callees", "form", "gas", "heap_digest", "reply", "divides", "events")
    tsv("outcomes.tsv", header, result["outcomes"])
    tsv("vector-outcomes.tsv", header, result["vector_rows"])
    tsv("model-variants.tsv", ("switch", "outcome", "first_case"), result["variants"])
    tsv("structural-controls.tsv", ("control", "outcome"), result["structural"])
    tsv("unreached-rows.tsv", ("class", "rows", "addresses"), [("not reached by any case", len(result["unreached"]), " ".join("%#x" % va for va in result["unreached"])),
                                                              ("reached only with injected callee answers", len(result["stub_only"]),
                                                               " ".join("%#x" % va for va in result["stub_only"]))])
    tsv("rust-vectors.tsv", ("tag", "optional", "plus_0x10", "plus_0x18", "a", "ia", "b", "ib", "min", "max", "bend", "kink", "reserve", "words_or_refused"),
        [row[:13] + [" ".join(row[13:])] for row in result["rust"]])
    mutations = result.get("mutations", [])
    if mutations:
        tsv("mutations.tsv", ("address", "kind", "outcome", "detail"), [("%#x" % va, kind, outcome, detail) for va, kind, outcome, detail in mutations])
    killed = sum(1 for row in mutations if row[2] == "killed")
    variants_detected = sum(1 for row in result["variants"] if row[1] == "detected")
    structural_detected = sum(1 for row in result["structural"] if row[1] == "detected")
    if variants_detected != len(result["variants"]) or structural_detected != len(result["structural"]):
        raise EvidenceError("a negative control was missed")
    start, end = result["fde"]
    summary = {
        "binary": "artifacts/node/115/hl-node", "sha256": SHA256,
        "function": {"address": "%#x" % start, "fde_end": "%#x" % end, "fde_bytes": end - start, "body_end": "%#x" % BODY_END, "body_bytes": BODY_END - start,
                     "body_instructions": len(rows), "landing_pad_bytes_not_run": end - BODY_END},
        "table": {"slot": "%#x" % TABLE_SLOT, "address_bytes": result["table"][1][1]},
        "named_cases": len(result["cases"]), "named_cases_with_injected_callees": sum(1 for _, stubbed in result["cases"] if stubbed),
        "vector_cases": result["vector_count"], "vector_cases_with_injected_callees": result["stub_count"],
        "rows_not_reached": ["%#x" % va for va in result["unreached"]], "rows_reached_only_with_injected_callees": len(result["stub_only"]),
        "model_variants": len(result["variants"]), "structural_controls": len(result["structural"]), "rust_vectors": len(result["rust"]),
    }
    if mutations:
        summary["mutations"] = {"total": len(mutations), "killed": killed, "survived": len(mutations) - killed,
                                "injected_only": sum(1 for row in mutations if row[3] == "injected callee answers only")}
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    controls = len(result["variants"]) + len(result["structural"]) + killed
    files["measure.json"] = json.dumps({"cases": len(result["cases"]) + result["vector_count"], "negative_controls": controls,
                                        "negative_detected": variants_detected + structural_detected + killed}, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--vectors", type=int, default=9000)
    parser.add_argument("--no-mutants", action="store_true")
    args = parser.parse_args(argv)
    image = load_image()
    files = render(analyse(image, vectors=args.vectors, mutate=not args.no_mutants))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="ascii", newline="\n")
    print(json.dumps({"files": sorted(files)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
