#!/usr/bin/env python3
"""Reconstruct the node #115 BOLE per-user reply 0x38e5d00: the bytes run from the ELF against a separately written rule list.

0x38e5d00 is the callback stored for address 0x...0811 in the read table at 0x646e738. It charges 1000 + 33 per input byte, parses a
20 byte key and a token index, checks the token against a count and a token store (a B-tree or a sorted ring), finds a per-key value
through 0x369a210 (a B-tree or ring keyed by 20 bytes with a lazily built empty default), finds the token in that value's ordered map
(B-tree or ring of 32 byte values), runs 0x46df170 on the 32 byte value (two lookups of the same token record, two 64x64 products,
two 128 bit divides by 1e14) and returns four 32 byte big-endian words. The real bytes of 0x38e5d00, 0x46df170, 0x369a210 and 0x35bf460
run in the shared offline interpreter (tools/x86_115.py); every other external call is a recording stub that checks its arguments. A
rule list written separately predicts the result words, every heap byte, the lazy static, and the ordered stub requests (with divides).
Wrong readings of the rule list, structural controls and byte edits of the four bodies are run as negative controls. No objdump or
readelf output is parsed and the binary is never executed. Field and role names below are inference; offsets and arithmetic are what
the bytes show. Standard library only.

    python3 tools/bole_user_reply115.py --out <dir> [--vectors N] [--no-mutants]
"""

import argparse
import hashlib
import json
import pathlib
import struct
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from x86_115 import (  # noqa: E402
    HEAP_BASE, MARK_BASE, POISON, R8, RAX, RCX, RDI, RDX, RSI, SHA256, EvidenceError, Halt, Machine, Panicked, decode_range, load_image,
)

ENTRY = 0x38E5D00
BODY_END = 0x38E63DD  # first landing pad; the normal body ends with the ud2 at 0x38e63db, [BODY_END, FDE end) is unwind cleanup
TABLE_SLOT = 0x646E738
PAIRS, PAIRS_END = 0x46DF170, 0x46DF355  # 0x46df170: the two (tag, word, quotient) pairs
USERS, USERS_END = 0x369A210, 0x369A3C2  # 0x369a210: per-key value lookup with a lazy default
TREE, TREE_END = 0x35BF460, 0x35BF4F2  # 0x35bf460: token B-tree search used by 0x46df170
REAL = (PAIRS, USERS, TREE)
FUNCTIONS = ((ENTRY, BODY_END, "body"), (PAIRS, PAIRS_END, "pairs"), (USERS, USERS_END, "users"), (TREE, TREE_END, "tree_search"))

PARSE, DROP_PARSE, FMT_A, DROP_CODE = 0x3897020, 0x38F9750, 0x46DE430, 0x3D57B80
TOKEN_SEARCH, UMAP_SEARCH, USER_SEARCH = 0x4556410, 0x455B7B0, 0x4555250
SLOT_ALLOC, SLOT_FREE, SLOT_ALLOC_ERR, SLOT_BYTES, SLOT_DIV = 0x64DF480, 0x64DF4A0, 0x64DF498, 0x64DF948, 0x64DFAF8
SLOT_FMT_B, SLOT_USERS, SLOT_ONCE, SLOT_MEMCMP = 0x64E9570, 0x64E6498, 0x64DF9F0, 0x64DFB50
SLOT_TARGETS = {SLOT_ALLOC: 0x6355830, SLOT_FREE: 0x635DE30, SLOT_ALLOC_ERR: 0x141E264, SLOT_BYTES: 0x161CC70, SLOT_DIV: 0x63EFEC0,
                SLOT_FMT_B: 0x3D4EB60, SLOT_USERS: USERS, SLOT_ONCE: 0x5C87D50}
LAZY, LAZY_STATE, LAZY_INIT = 0x64FB8B0, 0x64FB8E8, 0x3714110  # lazy static value (0x38 bytes), its once state, its init function
ONCE_VTABLE, ONCE_LOCATION = 0x6468CE8, 0x6468D10
# What 0x3714110 writes into the lazy value (checked by running its bytes in structural_controls): offset -> (size, value).
DEFAULT_WRITES = ((0x20, 8, 0), (0x28, 8, 0xF6401A), (0x30, 4, 0), (0x00, 8, 0), (0x08, 8, 8), (0x10, 8, 0), (0x18, 8, 0))
LAZY_FILE_STATE = 3  # the once state word in the file image (0 is the completed state: the body calls the once only when nonzero)

E14, TOP = 10 ** 14, (1 << 64) - 1
OUT_OF_GAS = 0x8000000000000001
BTREE_TAG = 0x8000000000000000
REPLY_SIZE, BOX_SIZE, TEXT = 0x80, 0x20, b"Invalid input"
BASE_GAS, GAS_PER_BYTE, MAX_INPUT = 1000, 33, 2000
CODE_COUNT, CODE_MISS = 0xFA, 0xF1

# Fixture addresses inside the interpreter heap.
OUT, CTX, HOLD_A, STORE_S, INPUT, VTABLE = (HEAP_BASE + offset for offset in (0x100, 0x200, 0x300, 0x400, 0x800, 0x1800))
ALLOCS, POOL = HEAP_BASE + 0x2000, HEAP_BASE + 0x3000
USED = 0x40000
DATA_WORD = 0x5150
MARK_DROP = MARK_BASE + 0x99000
BACKGROUND = bytes(((index * 13) ^ (index >> 8)) & 0xFF or 1 for index in range(USED))
ADDR = bytes(range(0x10, 0x24))  # the default 20 byte key

# Token store (S+0x58): B-tree node keys at +0x798, length u16 at +0x7f2, edges at +0x7f8, 0xb0 byte records from +0; ring entries 0xb8.
T_NODE, T_REC, T_ENTRY, T_KEYS, T_LEN, T_EDGES = 0x858, 0xB0, 0xB8, 0x798, 0x7F2, 0x7F8
# Key store (S+0x88): B-tree values (0x38) from +8, 20 byte keys at +0x270, length u16 at +0x34e, edges at +0x350; ring entries 0x50, value at +0x18.
U_NODE, U_VAL, U_KEY, U_KEYS, U_LEN, U_EDGES, U_ENTRY, U_ENTRY_VAL = 0x3B0, 0x38, 20, 0x270, 0x34E, 0x350, 0x50, 0x18
# Per-key token map (value header +0..+0x20): B-tree 32 byte values from +0, keys at +0x168, length u16 at +0x1c2, edges at +0x1c8; ring entries 0x28.
M_NODE, M_VAL, M_KEYS, M_LEN, M_EDGES, M_ENTRY = 0x228, 0x20, 0x168, 0x1C2, 0x1C8, 0x28

VARIANTS = (
    "gas_32", "gas_base_0", "len_2001", "gas_ge", "gas_no_reply", "gas_wrap", "count_le", "token_at_8", "addr_at_10", "parse_any_tag",
    "miss_extra_1", "user_miss_fmt_a", "store_miss_fmt_b", "ring_bit_first", "umap_ring_no_len", "umap_ring_no_wrap", "user_ring_no_len",
    "user_ring_no_wrap", "user_miss_refuse", "once_skip", "once_only_on_miss", "half2_field_58", "half1_field_78", "mul_v10", "div_e10",
    "round_up", "guard_le", "no_guard", "miss_tag_set", "little_endian", "word_order", "clear_one_word", "tag2_from_tag1",
    "one_half_lookup", "memcmp_swapped", "tree_last_edge", "box_free_first", "text_len_12", "quotient_high",
)


def fmt_words(code, extra):
    """What the two message-building stubs answer: three words that name the request."""
    return (0xC0DE0000 | code, 0xFACE0000 | (extra & 0xFFFF), 0xBEEF0000 | ((extra >> 16) & 0xFFFF))


class Case:
    """One call. Defaults: token 7 found in a one-leaf token tree, key ADDR found in a one-leaf key tree, its map holds token 7."""

    def __init__(self, name, **fields):
        self.name = name
        self.input_len, self.gas = 32, 1 << 40
        self.parse = ("ok", 7)  # ("ok", token) / ("err", tag byte)
        self.addr = ADDR
        self.count = 100
        self.store = ("tree", 0, 3)  # token store: ("tree", height, separators) / ("ring", capacity, head) / ("none", height)
        self.keys = [7]
        self.rec = (E14, E14)  # the subject token record's u64 at +0x58 and +0x78
        self.users = ("tree", 0, 3)  # key store, same forms
        self.user_keys = [ADDR]
        self.umap = ("tree", 0, 3)  # the subject key's token map, same forms
        self.umap_keys = [7]
        self.value = (11, 22 * E14, 33, 44 * E14)  # the subject 32 byte value as four u64
        self.once = 0  # lazy static once state at entry (0 = completed)
        self.tok_answers = None  # injected (rax, rdx) answers of the token ring search, by call
        self.user_answers = None
        self.umap_answers = None
        self.faults = {}  # injected 128 bit quotients by divide index
        self.cmp = "unit"  # memcmp answer shape: unit / diff / wide
        self.fail_alloc = None
        self.reply_len = REPLY_SIZE  # the length the bytes constructor reports
        for key, value in fields.items():
            if not hasattr(self, key):
                raise KeyError(key)
            setattr(self, key, value)

    def token(self):
        return self.parse[1]


def parse_block(case):
    """The 0x58 byte parse result the parser stub writes: tag at +0; on success the 20 byte key at +8 and the token at +0x20."""
    block = bytearray((0x40 + 3 * index) & 0xFF for index in range(0x58))
    if case.parse[0] == "ok":
        block[0] = 0x0C
        block[8:0x1C] = case.addr
        struct.pack_into("<Q", block, 0x20, case.parse[1] & TOP)
    else:
        block[0] = case.parse[1] & 0xFF
    return bytes(block)


def other_value(seed):
    return ((seed * 0x9E3779B97F4A7C15 + 1) & TOP, (seed * 7 + 3) * E14 % (1 << 63), (seed * 0xC2B2AE3D27D4EB4F + 5) & TOP, (seed * 13 + 1) * E14 % (1 << 62))


def other_rec(key):
    return ((key * 3 + 1) * 10 ** 12 + 7, (key * 5 + 2) * 10 ** 12 + 9)


def record_bytes(fields):
    data = bytearray((0x31 + 7 * index) & 0xFF for index in range(T_REC))
    struct.pack_into("<Q", data, 0x58, fields[0] & TOP)
    struct.pack_into("<Q", data, 0x78, fields[1] & TOP)
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


def tree_capacity(height, separators):
    count = max(1, min(separators, 11))
    total = 11
    for _ in range(height):
        total = total * (count + 1) + count
    return total


def ring_search(keys, key):
    """Ok(index) as (0, index), Err(insertion) as (1, insertion)."""
    low, high = 0, len(keys)
    while low < high:
        mid = (low + high) // 2
        if keys[mid] < key:
            low = mid + 1
        else:
            high = mid
    return (0, low) if low < len(keys) and keys[low] == key else (1, low)


class Layout:
    """Writes one case into heap bytes and remembers where each value went."""

    def __init__(self, case):
        self.case = case
        self.data = bytearray(BACKGROUND)
        self.next = POOL
        self.token_at = {}  # token -> record address
        self.user_at = {}  # key -> value (map header) address
        self.maps = {}  # map header address -> (form, sorted keys, shape, value addresses)
        self.token_shape = self.user_shape = None
        self.token_buf = self.user_buf = None
        self.put(CTX + 0x10, HOLD_A)
        self.put(CTX + 0x48, STORE_S)
        self.put(HOLD_A + 0x38, case.count)
        self.put(VTABLE + 0x20, MARK_DROP)
        self.build_tokens()
        self.build_users()

    def put(self, addr, value, size=8):
        self.data[addr - HEAP_BASE:addr - HEAP_BASE + size] = (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")

    def blob(self, addr, data):
        self.data[addr - HEAP_BASE:addr - HEAP_BASE + len(data)] = data

    def word(self, addr):
        return struct.unpack_from("<Q", self.data, addr - HEAP_BASE)[0]

    def inside(self, addr, size):
        return HEAP_BASE <= addr and addr + size <= HEAP_BASE + USED

    def take(self, size):
        at = self.next
        self.next += (size + 15) & ~15
        if self.next > HEAP_BASE + USED:
            raise ValueError("fixture does not fit")
        return at

    def tree_nodes(self, shape, node_size, keys_at, len_at, edges_at, write_key, write_value, key_size=8):
        own, children = shape
        at = self.take(node_size)
        for index, key in enumerate(own):
            write_key(at, keys_at, index, key)
            write_value(at, index, key)
        for index in range(len(own), 11):
            # unused key slots hold zero, so a walk that reads past the length goes on instead of stopping where the length would
            self.blob(at + keys_at + key_size * index, bytes(key_size))
        struct.pack_into("<H", self.data, at + len_at - HEAP_BASE, len(own))
        for index, child in enumerate(children):
            self.put(at + edges_at + 8 * index, self.tree_nodes(child, node_size, keys_at, len_at, edges_at, write_key, write_value, key_size))
        return at

    def header(self, at, form, root_or_buf, third, length):
        if form[0] == "ring":
            self.put(at, form[1])
        else:
            self.put(at, BTREE_TAG)
        self.put(at + 8, root_or_buf)
        self.put(at + 0x10, third)
        self.put(at + 0x18, length)

    def build_tokens(self):
        case = self.case
        form = case.store
        keys = sorted(case.keys)

        def record(key):
            return record_bytes(case.rec if key == case.token() else other_rec(key))

        def key_u64(node, keys_at, index, key):
            self.put(node + keys_at + 8 * index, key)

        if form[0] == "tree":
            self.token_shape = tree_shape(keys, form[1], form[2])

            def value(node, index, key):
                self.blob(node + T_REC * index, record(key))
                self.token_at[key] = node + T_REC * index

            def tree_key(node, keys_at, index, key):
                key_u64(node, keys_at, index, key)

            root = self.tree_nodes(self.token_shape, T_NODE + 8, T_KEYS, T_LEN, T_EDGES, tree_key, value)
            self.header(STORE_S + 0x58, form, root, form[1], len(keys))
        elif form[0] == "ring":
            capacity, head = form[1], form[2]
            buf = self.take(max(capacity, 1) * T_ENTRY)
            self.token_buf = buf
            for index, key in enumerate(keys):
                at = buf + ((head + index) % capacity) * T_ENTRY
                self.put(at, key)
                self.blob(at + 8, record(key))
                self.token_at[key] = at + 8
            self.header(STORE_S + 0x58, form, buf, head, len(keys))
        else:
            self.header(STORE_S + 0x58, ("tree",), 0, form[1] if len(form) > 1 else 0, 0)

    def build_map(self, at, form, entries):
        """A token map at header address `at`: entries is {token: (four u64)}."""
        keys = sorted(entries)
        where = {}

        def value(node, index, key):
            self.blob(node + M_VAL * index, struct.pack("<4Q", *(word & TOP for word in entries[key])))
            where[key] = node + M_VAL * index

        def tree_key(node, keys_at, index, key):
            self.put(node + keys_at + 8 * index, key)

        shape = None
        if form[0] == "tree":
            shape = tree_shape(keys, form[1], form[2])
            root = self.tree_nodes(shape, M_NODE, M_KEYS, M_LEN, M_EDGES, tree_key, value)
            self.header(at, form, root, form[1], len(keys))
        elif form[0] == "ring":
            capacity, head = form[1], form[2]
            buf = self.take(2 * max(capacity, 1) * M_ENTRY)
            # every slot not holding a key, and the capacity slots past the end, hold a decoy entry, so a wrong slot reads a real entry
            for slot in range(2 * max(capacity, 1)):
                self.put(buf + slot * M_ENTRY, 0xDEC0 + slot)
                self.blob(buf + slot * M_ENTRY + 8, struct.pack("<4Q", *other_value(0xDEC0 + slot)))
            for index, key in enumerate(keys):
                slot = buf + ((head + index) % capacity) * M_ENTRY
                self.put(slot, key)
                self.blob(slot + 8, struct.pack("<4Q", *(word & TOP for word in entries[key])))
                where[key] = slot + 8
            self.header(at, form, buf, head, len(keys))
        else:
            self.header(at, ("tree",), 0, form[1] if len(form) > 1 else 0, 0)
        self.maps[at] = (form, keys, shape, where)

    def user_value(self, at, key):
        """Fill the 0x38 byte value of one key: the map header (+0..+0x20) then filler."""
        case = self.case
        self.user_at[key] = at
        if key == case.addr:
            entries = {token: (other_value(token) if token != case.token() else case.value) for token in case.umap_keys}
            self.build_map(at, case.umap, entries)
        else:
            seed = int.from_bytes(key[-4:], "little")
            self.build_map(at, ("ring", 2, seed % 2), {case.token() if case.parse[0] == "ok" else 7: other_value(seed)})

    def build_users(self):
        case = self.case
        form = case.users
        keys = sorted(case.user_keys)
        if form[0] == "tree":
            self.user_shape = tree_shape(keys, form[1], form[2])
            pending = []

            def value(node, index, key):
                pending.append((node + 8 + U_VAL * index, key))

            def tree_key(node, keys_at, index, key):
                self.blob(node + keys_at + U_KEY * index, key)

            root = self.tree_nodes(self.user_shape, U_NODE, U_KEYS, U_LEN, U_EDGES, tree_key, value, U_KEY)
            for at, key in pending:
                self.user_value(at, key)
            self.header(STORE_S + 0x88, form, root, form[1], len(keys))
        elif form[0] == "ring":
            capacity, head = form[1], form[2]
            buf = self.take(2 * max(capacity, 1) * U_ENTRY)
            self.user_buf = buf
            used = {(head + index) % capacity for index in range(len(keys))}
            # empty slots and the capacity slots past the end hold decoy keys whose map holds the token, so a wrong slot reads a real value
            for slot in range(2 * max(capacity, 1)):
                if slot not in used:
                    decoy = bytes([0xEE] * 19 + [slot])
                    self.blob(buf + slot * U_ENTRY, decoy)
                    self.user_value(buf + slot * U_ENTRY + U_ENTRY_VAL, decoy)
            for index, key in enumerate(keys):
                at = buf + ((head + index) % capacity) * U_ENTRY
                self.blob(at, key)
                self.user_value(at + U_ENTRY_VAL, key)
            self.header(STORE_S + 0x88, form, buf, head, len(keys))
        else:
            self.header(STORE_S + 0x88, ("tree",), 0, form[1] if len(form) > 1 else 0, 0)


def lazy_statics(initialised):
    """The lazy static as the interpreter's static memory: before init the first word holds the init function, after it the default."""
    words = {LAZY + offset: 0 for offset in range(0, 0x38, 8)}
    if initialised:
        for offset, size, value in DEFAULT_WRITES:
            at = LAZY + (offset & ~7)
            shift = 8 * (offset & 7)
            words[at] = (words[at] & ~(((1 << (8 * size)) - 1) << shift)) | value << shift
    else:
        words[LAZY] = LAZY_INIT
    return words


# ----- the rule list (written from the block walk; shares no code with the interpreter) -----

def tree_find(node, key, height, m, compares=None):
    """First key not below the searched key; equal ends, else go down at that index (at the length when every key is below)."""
    own, children = node
    index = 0
    while index < len(own):
        if compares is not None:
            compares.append(own[index])
        greater = key < own[index] if "memcmp_swapped" in m and compares is not None else key > own[index]
        if not greater:
            break
        index += 1
    if index < len(own) and key == own[index]:
        return own[index]
    if height == 0:
        return None
    if index == len(own) and "tree_last_edge" in m and compares is None and index:
        index -= 1
    return tree_find(children[index], key, height - 1, m, compares)


def word32(value, m):
    if "little_endian" in m:
        return struct.pack("<Q", value & TOP) + bytes(24)
    return bytes(24) + struct.pack(">Q", value & TOP)


def spec(case, layout, m=frozenset()):
    """Returns (out words or None per word, heap writes, ordered events, statics after, panicked)."""
    events, writes = [], {}
    out = [None] * 5
    statics = lazy_statics(case.once == 0)

    def done(panicked=False):
        return out, writes, events, statics, panicked

    def refuse():
        out[0], out[1] = 0, OUT_OF_GAS
        return done()

    per_byte = 32 if "gas_32" in m else GAS_PER_BYTE
    base = (0 if "gas_base_0" in m else BASE_GAS) + per_byte * case.input_len
    if case.input_len > (MAX_INPUT + 1 if "len_2001" in m else MAX_INPUT) or (base >= case.gas if "gas_ge" in m else base > case.gas):
        return refuse()
    events.append(("parse", case.input_len))
    block = parse_block(case)
    if block[0] != 0x0C and not ("parse_any_tag" in m and block[0] == 0x0D):
        events.append(("drop_parse",))
        events.append(("alloc", len(TEXT)))
        if case.fail_alloc == 0:
            events.append(("alloc_error", 1, len(TEXT)))
            return done(True)
        size = 12 if "text_len_12" in m else len(TEXT)
        writes[ALLOCS] = TEXT
        out[0], out[1], out[2], out[3] = 0, size, ALLOCS, size
        return done()
    token = struct.unpack_from("<Q", block, 8 if "token_at_8" in m else 0x20)[0]
    addr = block[0x10:0x24] if "addr_at_10" in m else block[8:0x1C]

    def message(code, extra, second):
        if second:
            events.append(("fmt_b", code, extra))
        else:
            events.append(("fmt_a", code, extra, 0))
            events.append(("drop_code",))
        out[0] = 0
        out[1], out[2], out[3] = fmt_words(code, extra)
        return done()

    if (token > case.count) if "count_le" in m else (token >= case.count):
        return message(CODE_COUNT, token, False)
    miss_extra = 1 if "miss_extra_1" in m else 0

    # token store at S+0x58: only presence matters here
    form = case.store
    tok_keys = sorted(case.keys)
    tok_answers = list(case.tok_answers) if case.tok_answers else [ring_search(tok_keys, token)] * 3
    if form[0] == "ring":
        events.append(("lookup_token", token))
        flag = tok_answers[0][0]
        present = (flag & 1) == 0 if "ring_bit_first" in m else flag == 0
    elif form[0] == "tree":
        present = tree_find(layout.token_shape, token, form[1], m) is not None
    else:
        present = False
    if not present:
        return message(CODE_MISS, miss_extra, "store_miss_fmt_b" in m)

    # key lookup (0x369a210) at S+0x88
    value_at = None
    form = case.users
    user_keys = sorted(case.user_keys)
    if form[0] == "tree":
        compares = []
        found = tree_find(layout.user_shape, addr, form[1], m, compares)
        events.extend(("memcmp", key.hex()) for key in compares)
        if found is not None:
            value_at = layout.user_at[found]
    elif form[0] == "ring":
        events.append(("lookup_user", addr.hex()))
        flag, index = case.user_answers[0] if case.user_answers else ring_search(user_keys, addr)
        if not flag & 1 and (index < len(user_keys) or "user_ring_no_len" in m):
            slot = (form[2] + index) & TOP
            if slot >= form[1] and "user_ring_no_wrap" not in m:
                slot -= form[1]
            value_at = (layout.user_buf + slot * U_ENTRY + U_ENTRY_VAL) & TOP
    if value_at is None and "user_miss_refuse" in m:
        return message(CODE_MISS, miss_extra, "user_miss_fmt_a" not in m)
    if case.once != 0 and "once_skip" not in m and not ("once_only_on_miss" in m and value_at is not None):
        events.append(("once",))
        statics = lazy_statics(True)

    def fault(addr):
        # a wrong reading that addresses memory outside the fixture: the prediction is a fault at that address
        events.append(("fault", addr))
        return done()

    if value_at is not None and value_at not in layout.maps:
        return fault(value_at)
    # the key's token map
    entry_at = None
    if value_at is None:
        # the lazy default: capacity 0, buffer 8, head 0, length 0 -> ring form that holds nothing
        default = statics[LAZY], statics[LAZY + 8], statics[LAZY + 0x10], statics[LAZY + 0x18]
        if default[0] == BTREE_TAG:
            raise EvidenceError("default is not a ring")
        events.append(("lookup_umap", token, LAZY))
        flag, index = case.umap_answers[0] if case.umap_answers else ring_search([], token)
        if not flag & 1 and (index < default[3] or "umap_ring_no_len" in m):
            slot = (default[2] + index) & TOP
            if slot >= default[0] and "umap_ring_no_wrap" not in m:
                slot -= default[0]
            return fault((default[1] + slot * M_ENTRY + 8) & TOP)  # the default's buffer is the dangling pointer 8
    else:
        mform, mkeys, mshape, mwhere = layout.maps[value_at]
        if mform[0] == "tree":
            found = tree_find(mshape, token, mform[1], m)
            if found is not None:
                entry_at = mwhere[found]
        elif mform[0] == "ring":
            events.append(("lookup_umap", token, value_at))
            flag, index = case.umap_answers[0] if case.umap_answers else ring_search(mkeys, token)
            if not flag & 1 and (index < len(mkeys) or "umap_ring_no_len" in m):
                slot = (mform[2] + index) & TOP
                if slot >= mform[1] and "umap_ring_no_wrap" not in m:
                    slot -= mform[1]
                entry_at = (layout.word(value_at + 8) + slot * M_ENTRY + 8) & TOP
                if not layout.inside(entry_at, 32):
                    return fault(entry_at)
    if entry_at is None:
        return message(CODE_MISS, miss_extra, "user_miss_fmt_a" not in m)
    v0, v8, v10, v18 = struct.unpack_from("<4Q", layout.data, entry_at - HEAP_BASE)

    # 0x46df170: two halves, each looks the same token up in S+0x58 and scales one value word by one record word
    form = case.store
    divides = [0]

    def half(number, multiplier, offset):
        if form[0] == "ring":
            if not ("one_half_lookup" in m and number == 2):
                events.append(("lookup_token", token))
            flag, index = tok_answers[1 if "one_half_lookup" in m else number]
            if flag & 1 or index >= len(tok_keys):
                # on a miss the pair's word is what the register holds: r15 keeps v8 (first half), rax keeps the search flag (second)
                word = multiplier if number == 1 else flag & TOP
                return (1 if "miss_tag_set" in m else 0), word
            slot = form[2] + index
            if slot >= form[1]:
                slot -= form[1]
            rec_at = layout.token_buf + slot * T_ENTRY + 8
        else:
            rec_at = layout.token_at[token]
        field = layout.word(rec_at + offset)
        product = multiplier * field
        scale = 10 ** 10 if "div_e10" in m else E14
        events.append(("div", product, scale))
        index = divides[0]
        divides[0] += 1
        quotient = case.faults[index] if index in case.faults else product // scale
        if "round_up" in m and product % scale:
            quotient += 1
        high = product >> 64
        if "no_guard" in m:
            tag = 1
        else:
            tag = int(high <= E14 if "guard_le" in m else high < E14)
        word = (quotient >> 64) & TOP if "quotient_high" in m else quotient & TOP
        return tag, word

    tag1, q1 = half(1, v8, 0x78 if "half1_field_78" in m else 0x58)
    tag2, q2 = half(2, v10 if "mul_v10" in m else v18, 0x58 if "half2_field_58" in m else 0x78)
    if "tag2_from_tag1" in m:
        tag2 = tag1
    w = [v0 if tag1 else 0, q1 if tag1 else 0, (v18 if "mul_v10" in m else v10) if tag2 else 0, q2 if tag2 else 0]
    if "clear_one_word" in m:
        w = [v0 if tag1 else v0, q1 if tag1 else 0, v10 if tag2 else v10, q2 if tag2 else 0]
    if "word_order" in m:
        w = [w[2], w[3], w[0], w[1]]
    reply = b"".join(word32(word, m) for word in w)
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
    extra = 0 if "gas_no_reply" in m else per_byte * case.reply_len
    extra = min(extra, TOP)
    total = base + extra
    if total > TOP:
        total = total & TOP if "gas_wrap" in m else TOP
    if total > case.gas:
        events.append(("bytes_drop", case.reply_len))
        return refuse()
    out[0], out[1], out[2], out[3], out[4] = VTABLE, ALLOCS, case.reply_len & TOP, DATA_WORD, total
    return done()


# ----- the bytes -----

class Harness:
    def __init__(self, image, patches=None):
        self.image = image
        machine = Machine(image, patches)
        self.machine = machine
        machine.real = frozenset(REAL)
        for slot, hook in ((SLOT_ALLOC, self.on_alloc), (SLOT_FREE, self.on_free), (SLOT_ALLOC_ERR, self.on_alloc_error),
                           (SLOT_BYTES, self.on_bytes), (SLOT_DIV, self.on_div), (SLOT_FMT_B, self.on_fmt_b), (SLOT_ONCE, self.on_once),
                           (SLOT_MEMCMP, self.on_memcmp)):
            machine.slots[MARK_BASE + slot] = hook
        machine.slots[MARK_DROP] = self.on_bytes_drop
        machine.calls.update({PARSE: self.on_parse, DROP_PARSE: self.on_drop_parse, FMT_A: self.on_fmt_a, DROP_CODE: self.on_drop_code,
                              TOKEN_SEARCH: self.on_token_search, UMAP_SEARCH: self.on_umap_search, USER_SEARCH: self.on_user_search})
        self.case = self.layout = None
        self.events = []

    def statics(self, case):
        statics = self.machine.memory.statics
        statics.clear()
        for slot in (SLOT_ALLOC, SLOT_FREE, SLOT_ALLOC_ERR, SLOT_BYTES, SLOT_DIV, SLOT_FMT_B, SLOT_ONCE, SLOT_MEMCMP):
            statics[slot] = MARK_BASE + slot
        statics[SLOT_USERS] = USERS  # the relocated slot target runs from its real bytes
        statics.update(lazy_statics(case.once == 0))
        statics[LAZY_STATE] = case.once

    def expect(self, condition, text):
        if not condition:
            raise Halt("stub check failed: " + text)

    def read(self, addr):
        return self.machine.memory.read(addr, 8)

    def on_div(self, machine):
        regs = machine.regs
        num, den = regs[RDI] | regs[RSI] << 64, regs[RDX] | regs[RCX] << 64
        index = sum(1 for event in self.events if event[0] == "div")
        self.events.append(("div", num, den))
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
        self.parsed = parse_block(self.case)
        machine.memory.put_bytes(regs[RDI], self.parsed)

    def on_drop_parse(self, machine):
        self.expect(machine.memory.bytes_at(machine.regs[RDI], 0x58) == self.parsed, "the refused parse result is passed on whole")
        self.events.append(("drop_parse",))

    def on_alloc(self, machine):
        size = machine.regs[RDI]
        index = self.allocs
        self.allocs += 1
        self.events.append(("alloc", size))
        self.expect(size <= 0x200, "allocation fits the fixture")
        machine.regs[RAX] = 0 if self.case.fail_alloc == index else ALLOCS + 0x200 * index

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
        return code, (memory.read(addr + 8, 8) if code == CODE_COUNT else memory.read(addr + 2, 1))

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

    def answer(self, machine, injected, number, computed):
        flag, where = injected[number] if injected else computed
        machine.regs[RAX], machine.regs[RDX] = flag & TOP, where & TOP
        machine.keep_rdx = True

    def on_token_search(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STORE_S + 0x58, "token search receives the token store")
        key = self.read(regs[RSI])
        number = sum(1 for event in self.events if event[0] == "lookup_token")
        self.events.append(("lookup_token", key))
        self.answer(machine, self.case.tok_answers, number, ring_search(sorted(self.case.keys), key))

    def on_user_search(self, machine):
        regs = machine.regs
        self.expect(regs[RDI] == STORE_S + 0x88, "key search receives the key store")
        key = machine.memory.bytes_at(regs[RSI], 20)
        self.events.append(("lookup_user", key.hex()))
        self.answer(machine, self.case.user_answers, 0, ring_search(sorted(self.case.user_keys), key))

    def on_umap_search(self, machine):
        regs = machine.regs
        at = regs[RDI]
        key = self.read(regs[RSI])
        self.events.append(("lookup_umap", key, at))
        keys = self.layout.maps[at][1] if at in self.layout.maps else []
        self.expect(at in self.layout.maps or at == LAZY, "map search receives a map")
        self.answer(machine, self.case.umap_answers, 0, ring_search(keys, key))

    def on_memcmp(self, machine):
        regs = machine.regs
        self.expect(regs[RDX] == 20, "memcmp length")
        left, right = machine.memory.bytes_at(regs[RDI], 20), machine.memory.bytes_at(regs[RSI], 20)
        self.expect(left == self.case.addr, "memcmp left operand is the parsed key")
        self.events.append(("memcmp", right.hex()))
        diff = next((index for index in range(20) if left[index] != right[index]), None)
        if diff is None:
            value = 0
        elif self.case.cmp == "diff":
            value = left[diff] - right[diff]
        elif self.case.cmp == "wide":
            value = (0x40000000 + diff) * (1 if left[diff] > right[diff] else -1)
        else:
            value = 1 if left[diff] > right[diff] else -1
        regs[RAX] = (value & 0xFFFFFFFF) | (0xDEADBEEF << 32 if self.case.cmp == "wide" else (TOP ^ 0xFFFFFFFF if value < 0 else 0))

    def on_once(self, machine):
        regs = machine.regs
        memory = machine.memory
        self.expect(regs[RDI] == LAZY_STATE and regs[RSI] & 0xFFFFFFFF == 1 and regs[RCX] == ONCE_VTABLE and regs[R8] == ONCE_LOCATION,
                    "once arguments")
        self.expect(memory.read(memory.read(regs[RDX], 8), 8) == LAZY, "once closure reaches the lazy value")
        self.events.append(("once",))
        memory.statics.update(lazy_statics(True))
        memory.statics[LAZY_STATE] = 0

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

    def run(self, case):
        layout = Layout(case)
        machine = self.machine
        memory = machine.memory
        memory.reset(USED)
        memory.put_bytes(HEAP_BASE, bytes(layout.data))
        machine.xmm = [POISON | POISON << 64] * 16
        self.statics(case)
        self.case, self.layout = case, layout
        self.events, self.allocs = [], 0
        self.parsed = self.code_addr = None
        before = bytes(layout.data)
        panicked = False
        try:
            value = machine.run(ENTRY, {RDI: OUT, RSI: CTX, RDX: INPUT, RCX: case.input_len, R8: case.gas})
            if value != OUT:
                raise Halt("result pointer")
        except Panicked:
            panicked = True
        statics = {addr: memory.statics[addr] for addr in lazy_statics(True)}
        statics_state = memory.statics[LAZY_STATE]
        return layout, before, bytes(memory.heap[:USED]), list(self.events), (statics, statics_state), panicked


def expected_heap(before, out, writes):
    data = bytearray(before)
    for index, word in enumerate(out):
        if word is not None:
            struct.pack_into("<Q", data, OUT - HEAP_BASE + 8 * index, word)
    for addr, blob in writes.items():
        data[addr - HEAP_BASE:addr - HEAP_BASE + len(blob)] = blob
    return bytes(data)


def judge(run, case, m=frozenset(), tamper=None):
    """None when a run of the bytes and the rule list agree on every heap byte, every event, the lazy static and the panic; else the
    difference. `tamper` edits the expected side; it is used only by the comparator self-tests."""
    layout, before, after, events, (statics, state), panicked = run
    out, writes, want_events, want_statics, want_panic = spec(case, layout, m)
    want_state = 0 if any(event[0] == "once" for event in want_events) else case.once
    want_heap = expected_heap(before, out, writes)
    if tamper is not None:
        want_events, want_heap, want_statics, want_state = tamper(list(want_events), want_heap, dict(want_statics), want_state)
    if panicked != want_panic:
        return "panic"
    if events != want_events:
        return "events %r against %r" % (events, want_events)
    if statics != want_statics or state != want_state:
        return "lazy static"
    if not panicked and after != want_heap:
        return "heap bytes"
    return None


def compare(harness, case, m=frozenset()):
    return judge(harness.run(case), case, m)


def classify(after, events, panicked):
    words = struct.unpack_from("<5Q", after, OUT - HEAP_BASE)
    if panicked:
        return "panic", words
    if words[0] == 0:
        if words[1] == OUT_OF_GAS:
            return "out of gas", words
        if words[1] == len(TEXT) and words[2] == ALLOCS:
            return "invalid input", words
        code = [event for event in events if event[0] in ("fmt_a", "fmt_b")][-1]
        return "code %#x via %s" % (code[1], code[0]), words
    return "reply", words


def digest_row(harness, case):
    layout, before, after, events, _, panicked = harness.run(case)
    form, words = classify(after, events, panicked)
    reply = after[ALLOCS - HEAP_BASE:ALLOCS - HEAP_BASE + REPLY_SIZE] if form == "reply" else b""
    return (case.name, form, words[4] if form == "reply" else "-", hashlib.sha256(after).hexdigest()[:16], reply.hex() if reply else "-",
            sum(1 for event in events if event[0] == "div"), " ".join(event[0] for event in events))


# ----- cases -----

def injected_kinds(case):
    """What a case injects that consistent stores and working callees would not give: search answers that disagree with the store, divide
    quotients, a reply length other than 0x80, an allocation failure, or a once state other than completed (0) or the file's value (3)
    (the once stub always completes the init, which a running or poisoned once would not)."""
    kinds = []
    if case.tok_answers or case.user_answers or case.umap_answers:
        kinds.append("search answers")
    if case.faults:
        kinds.append("quotients")
    if case.reply_len != REPLY_SIZE:
        kinds.append("reply length")
    if case.fail_alloc is not None:
        kinds.append("allocation failure")
    if case.once not in (0, LAZY_FILE_STATE):
        kinds.append("once state")
    return kinds


def injected(case):
    return bool(injected_kinds(case))


def named_cases():
    rows = []

    def add(name, **fields):
        rows.append(Case(name, **fields))

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
    add("whole charge at 32 a byte", input_len=100, gas=BASE_GAS + 32 * 100 + 32 * REPLY_SIZE)
    for tag in (0, 1, 0x0B, 0x0D, 0x8C, 0xFF):
        add("parse refused with tag %#x" % tag, parse=("err", tag))
    add("parse refused, text allocation fails", parse=("err", 3), fail_alloc=0)
    add("parse refused at the smallest gas", parse=("err", 3), gas=BASE_GAS + GAS_PER_BYTE * 32)
    for token, count in ((0, 0), (0, 1), (7, 7), (7, 8), (8, 7), (TOP, TOP), (TOP - 1, TOP), (5, TOP)):
        add("token %d against count %d" % (token, count), parse=("ok", token), count=count, keys=[token], umap_keys=[token])
    add("token whose low bytes match the key", parse=("ok", 0x1716151413121110), count=TOP, keys=[0x1716151413121110],
        umap_keys=[0x1716151413121110])
    for label, fields in (("token tree", dict(store=("tree", 1, 1), keys=[7, 0x200000, 0x7FFFFF])), ("token ring", dict(store=("ring", 4, 3), keys=[7, 0x200000])),
                          ("map tree", dict(keys=[0x123456], umap_keys=[7, 0x200000])), ("map ring", dict(keys=[0x123456], umap=("ring", 3, 2), umap_keys=[7])),
                          ("missing key", dict(keys=[0x123456], user_keys=[]))):
        add("%s misses a token with a nonzero byte 2" % label, parse=("ok", 0x123456), count=TOP, **dict(dict(umap_keys=[0x123456]), **fields))
    add("empty token store", store=("none",))
    add("empty token store with a height", store=("none", 3))
    spread = [3, 7, 11, 19, 23, 31, 43, 47, 59, 61, 71, 79, 83, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163]
    shapes = ((0, 3, spread[:1]), (0, 3, spread[:2]), (0, 3, spread[:11]), (1, 1, spread[:3]), (1, 3, spread[:15]), (1, 11, spread[:27]),
              (2, 2, spread[:26]), (2, 3, spread[:27]), (1, 2, []), (2, 1, spread[:1]))
    for height, separators, keys in shapes:
        label = "token tree height %d, %d separators, %d keys" % (height, separators, len(keys))
        for token in sorted(set(keys[:1] + keys[-1:] + keys[len(keys) // 2:len(keys) // 2 + 1] + keys[1:2])):
            add("%s, token %d found" % (label, token), parse=("ok", token), keys=keys, store=("tree", height, separators), count=1000,
                umap_keys=[token])
        probes = [0, 1000] + ([keys[0] + 1, keys[-1] - 1] if len(keys) > 2 else []) + ([keys[len(keys) // 2] + 1] if keys else [])
        for token in sorted(set(probes) - set(keys)):
            add("%s, token %d missing" % (label, token), parse=("ok", token), keys=keys, store=("tree", height, separators), count=2000,
                umap_keys=[token])
    for token in spread[:27]:
        add("token tree height 2, every key, token %d" % token, parse=("ok", token), keys=spread[:27], store=("tree", 2, 2), count=1000,
            umap_keys=[token])
    ring = [5, 9, 14, 20, 33, 41]
    for capacity, head in ((6, 0), (6, 5), (8, 3), (8, 7), (16, 0), (7, 6)):
        for token in ring:
            add("token ring capacity %d head %d, token %d found" % (capacity, head, token), parse=("ok", token), keys=ring,
                store=("ring", capacity, head), umap_keys=[token])
        for token in (0, 6, 21, 99):
            add("token ring capacity %d head %d, token %d missing" % (capacity, head, token), parse=("ok", token), keys=ring,
                store=("ring", capacity, head), umap_keys=[token])
    add("token ring empty", parse=("ok", 5), keys=[], store=("ring", 4, 2), umap_keys=[5])
    # injected token ring answers: (main, first half, second half)
    for label, answers in (("main answers 1", [(1, 2), (0, 2), (0, 2)]), ("main answers 2", [(2, 2), (0, 2), (0, 2)]),
                           ("main answers 2^32", [(1 << 32, 2), (0, 2), (0, 2)]), ("main answers 0x100", [(0x100, 2), (0, 2), (0, 2)]),
                           ("main found with a huge index", [(0, TOP), (0, 2), (0, 2)]),
                           ("first half misses", [(0, 2), (1, 2), (0, 2)]), ("second half misses", [(0, 2), (0, 2), (1, 2)]),
                           ("both halves miss", [(0, 2), (1, 2), (1, 2)]), ("first half answers 2", [(0, 2), (2, 2), (0, 2)]),
                           ("second half answers 3", [(0, 2), (0, 2), (3, 2)]), ("second half answers 0x100", [(0, 2), (0, 2), (0x100, 2)]),
                           ("first half index at the length", [(0, 2), (0, 6), (0, 2)]), ("second half index past the length", [(0, 2), (0, 2), (0, 7)]),
                           ("halves at different indices", [(0, 2), (0, 1), (0, 4)]), ("halves at the last index", [(0, 2), (0, 5), (0, 5)]),
                           ("second half index is huge", [(0, 2), (0, 2), (0, TOP)])):
        add("token ring injected: %s" % label, parse=("ok", 14), keys=ring, store=("ring", 8, 5), umap_keys=[14], tok_answers=answers)
    # key store
    users = [bytes([0x10 + (index * 37) % 200] * 19 + [index]) for index in range(27)]
    near = [ADDR[:19] + bytes([value]) for value in (0x00, 0x22, 0x23, 0x24, 0xFF)] + [ADDR[:k] + bytes([ADDR[k] + 1]) + ADDR[k + 1:] for k in (0, 7, 13, 18)]
    near += [ADDR[:k] + bytes([ADDR[k] - 1]) + ADDR[k + 1:] for k in (0, 5, 19)]
    for height, separators, count in ((0, 3, 1), (0, 3, 11), (1, 1, 3), (1, 3, 15), (1, 11, 27), (2, 2, 26), (2, 3, 27)):
        keys = sorted(set(users[:count]))
        label = "key tree height %d, %d separators, %d keys" % (height, separators, len(keys))
        picks = sorted(set([keys[0], keys[-1], keys[len(keys) // 2], keys[min(1, len(keys) - 1)]]))
        for pick in picks:
            for cmp in ("unit", "diff", "wide"):
                add("%s, key %s found, memcmp %s" % (label, pick.hex()[:6] + pick.hex()[-2:], cmp), addr=pick, user_keys=keys,
                    users=("tree", height, separators), cmp=cmp)
        for probe in (bytes(20), b"\xff" * 20, keys[0][:19] + bytes([keys[0][19] + 100]), keys[-1][:19] + bytes([(keys[-1][19] + 1) & 0xFF])):
            if probe in keys:
                continue
            add("%s, key %s missing" % (label, probe.hex()[:6] + probe.hex()[-2:]), addr=probe, user_keys=keys, users=("tree", height, separators))
    near_keys = sorted(set(near + [ADDR]))
    for cmp in ("unit", "diff", "wide"):
        for height, separators in ((0, 3), (1, 2), (2, 1)):
            if len(near_keys) > tree_capacity(height, separators):
                continue
            add("near keys tree height %d, memcmp %s, found" % (height, cmp), user_keys=near_keys, users=("tree", height, separators), cmp=cmp)
            add("near keys tree height %d, memcmp %s, missing" % (height, cmp), user_keys=[key for key in near_keys if key != ADDR],
                users=("tree", height, separators), cmp=cmp)
    add("empty key store", users=("none",))
    add("empty key store with a height", users=("none", 2))
    add("key tree with an empty leaf", user_keys=[], users=("tree", 0, 3))
    ring_users = sorted(users[:6])
    for capacity, head in ((6, 0), (6, 5), (8, 3), (8, 7), (7, 6)):
        for pick in ring_users:
            add("key ring capacity %d head %d, key %s found" % (capacity, head, pick.hex()[:4] + pick.hex()[-2:]), addr=pick, user_keys=ring_users,
                users=("ring", capacity, head))
        add("key ring capacity %d head %d, key missing" % (capacity, head), user_keys=ring_users, users=("ring", capacity, head))
    for label, answer in (("answers 1", (1, 2)), ("answers 2", (2, 2)), ("answers 3", (3, 2)), ("answers 0x100", (0x100, 2)),
                          ("index at the length", (0, 6)), ("index past the length", (0, 7)), ("index is the last", (0, 5)), ("index is huge", (0, TOP)),
                          ("index 0", (0, 0))):
        add("key ring injected: %s" % label, addr=ring_users[2], user_keys=ring_users, users=("ring", 8, 5), user_answers=[answer])
    # lazy default
    for state in (0, 1, 2, 3, 4, 0xFFFFFFFF):
        add("lazy state %#x, key found" % state, once=state)
        add("lazy state %#x, key missing" % state, once=state, user_keys=[])
        add("lazy state %#x, key missing from a ring" % state, once=state, user_keys=ring_users, users=("ring", 8, 3))
    for label, answer in (("found at 0", (0, 0)), ("found at 1", (0, 1)), ("answers 2", (2, 0))):
        add("default map injected: %s" % label, user_keys=[], umap_answers=[answer])
    # per-key token map
    for height, separators, keys in shapes:
        label = "map tree height %d, %d separators, %d keys" % (height, separators, len(keys))
        for token in sorted(set(keys[:1] + keys[-1:] + keys[len(keys) // 2:len(keys) // 2 + 1] + keys[1:2])):
            add("%s, token %d found" % (label, token), parse=("ok", token), keys=[token], umap_keys=keys, umap=("tree", height, separators), count=1000)
        probes = [0, 1000] + ([keys[0] + 1, keys[-1] - 1] if len(keys) > 2 else []) + ([keys[len(keys) // 2] + 1] if keys else [])
        for token in sorted(set(probes) - set(keys)):
            add("%s, token %d missing" % (label, token), parse=("ok", token), keys=[token], umap_keys=keys, umap=("tree", height, separators), count=2000)
    for token in spread[:27]:
        add("map tree height 2, every key, token %d" % token, parse=("ok", token), keys=[token], umap_keys=spread[:27], umap=("tree", 2, 2), count=1000)
    add("empty map", umap=("none",))
    add("empty map with a height", umap=("none", 2))
    for capacity, head in ((6, 0), (6, 5), (8, 3), (8, 7), (16, 0), (7, 6)):
        for token in ring:
            add("map ring capacity %d head %d, token %d found" % (capacity, head, token), parse=("ok", token), keys=[token], umap_keys=ring,
                umap=("ring", capacity, head))
        for token in (0, 6, 99):
            add("map ring capacity %d head %d, token %d missing" % (capacity, head, token), parse=("ok", token), keys=[token], umap_keys=ring,
                umap=("ring", capacity, head))
    for label, answer in (("answers 1", (1, 2)), ("answers 2", (2, 2)), ("answers 3", (3, 2)), ("answers 0x100", (0x100, 2)),
                          ("index at the length", (0, 6)), ("index past the length", (0, 7)), ("index is the last", (0, 5)), ("index is huge", (0, TOP)),
                          ("index 0", (0, 0))):
        add("map ring injected: %s" % label, parse=("ok", 14), keys=[14], umap_keys=ring, umap=("ring", 8, 5), umap_answers=[answer])
    # arithmetic of 0x46df170
    edge = E14 << 64
    factors = (("zero", 0, 0), ("one", 1, 1), ("index 1.0", 5 * E14, E14), ("index 1.5", 3 * E14, 15 * 10 ** 13), ("just below 1e14", E14 - 1, 1),
               ("exactly 1e14", E14, 1), ("one above 1e14", E14 + 1, 1), ("largest words", TOP, TOP), ("product one below the guard", edge - 1, 1),
               ("guard by factors 2^63 * 2e14", 1 << 63, 2 * E14), ("guard minus one by factors", 3 * 13 * 7021362262547, 2039 * 1058093 * 3122429689),
               ("high word exactly 1e14 - 1", (1 << 63) - 1, 2 * E14), ("high word exactly 1e14 + 0", (1 << 63), 2 * E14),
               ("quotient 2^64 - 1", TOP, E14), ("quotient just at 2^64", (1 << 63) + 1, 2 * E14), ("rounding .99", 99, E14 // 100 + 1))
    for label, value, field in factors:
        if value > TOP or field > TOP:
            continue
        add("first half: %s" % label, value=(0x0102030405060708, value, 0x1112131415161718, 7 * E14), rec=(field, 3 * E14))
        add("second half: %s" % label, value=(0x0102030405060708, 7 * E14, 0x1112131415161718, value), rec=(3 * E14, field))
        add("both halves: %s" % label, value=(0x2122232425262728, value, 0x3132333435363738, value), rec=(field, field))
    # small words, and words whose low half is 0 or 1, in each of the four value positions (a misread flag dword would see them)
    for position in range(4):
        for word in (0, 1, (1 << 32) | 1, 1 << 32, 2):
            for store, keys in ((("tree", 0, 3), [7]), (("ring", 3, 2), [5, 7, 9])):
                value = [11, 22 * E14, 33, 44 * E14]
                value[position] = word
                add("value word %d is %#x, token %s" % (position, word, store[0]), value=tuple(value), store=store, keys=keys)
    for v0, v10 in ((0, 0), (1, 2), (TOP, 0), (0, TOP), (0x0102030405060708, 0x1112131415161718)):
        add("plain words %#x %#x" % (v0, v10), value=(v0, 3 * E14, v10, 5 * E14))
    for label, faults in (("first quotient injected", {0: 12345}), ("second quotient injected", {1: 54321}),
                          ("first quotient with a high word", {0: (1 << 64) | 77}), ("second quotient with a high word", {1: (5 << 64) | 99}),
                          ("both quotients injected", {0: TOP, 1: TOP - 1})):
        add("own divide: %s" % label, faults=faults)
    add("token ring, both halves found, distinct fields", parse=("ok", 20), keys=ring, store=("ring", 7, 4), umap_keys=[20], rec=(123 * E14, 456 * E14))
    add("reply allocation fails", fail_alloc=0)
    add("box allocation fails", fail_alloc=1)
    for label, size in (("zero", 0), ("one", 1), ("127", 127), ("129", 129), ("2^58", 1 << 58), ("the largest product that fits", TOP // 33),
                        ("the smallest product that overflows", TOP // 33 + 1), ("2^63", 1 << 63), ("the largest word", TOP)):
        add("reported reply length %s" % label, reply_len=size, gas=TOP)
        add("reported reply length %s, gas one below the largest word" % label, reply_len=size, gas=TOP - 1)
    add("reported reply length 129 at the whole charge of 128", reply_len=129, gas=BASE_GAS + GAS_PER_BYTE * 32 + GAS_PER_BYTE * REPLY_SIZE)
    add("out of gas after the reply, ring stores", store=("ring", 8, 2), keys=ring, parse=("ok", 9), umap=("ring", 8, 6), umap_keys=ring,
        users=("ring", 4, 3), user_keys=[ADDR], gas=BASE_GAS + GAS_PER_BYTE * 32 + GAS_PER_BYTE * REPLY_SIZE - 1)
    return rows


def lcg(seed):
    state = seed & TOP
    while True:
        state = (state * 6364136223846793005 + 1442695040888963407) & TOP
        yield state >> 11


def draw(stream):
    kind = next(stream) % 11
    value = next(stream) | next(stream) << 53
    if kind == 9:
        return value % 3
    if kind == 10:
        return (value & (TOP ^ 0xFFFFFFFF)) | value % 3
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
    if kind == 7:
        return (1 << 63) + value % (1 << 50)
    return value % (2 * E14)


def pick_form(stream, keys):
    """A store form that can hold the keys: ring, or a tree of height 0..2 cut to what fits."""
    if next(stream) % 2:
        capacity = len(keys) + next(stream) % 5
        return ("ring", max(capacity, 1), next(stream) % max(capacity, 1)), keys
    height = next(stream) % 3
    separators = 1 + next(stream) % 4
    if height == 1:
        separators = max(separators, 2)
    keys = keys[:tree_capacity(height, separators)]
    return ("tree", height, separators), keys


def vector_cases(count, seed=0x5EED0811):
    """Cases drawn from one stream."""
    stream = lcg(seed)
    prefixes = [bytes((next(stream) >> (8 * k)) & 0xFF for k in range(5)) * 4 for _ in range(3)]
    for number in range(count):
        choice = next(stream) % 100
        size = next(stream) % 2100 if choice < 6 else next(stream) % 400
        gas = TOP if choice >= 12 else BASE_GAS + GAS_PER_BYTE * size + next(stream) % (2 * GAS_PER_BYTE * REPLY_SIZE)
        scale = 0x10001 if next(stream) % 4 == 0 else 1
        tokens = sorted({next(stream) % 5000 * scale for _ in range(1 + next(stream) % 27)})
        store, tokens = pick_form(stream, tokens)
        token = tokens[next(stream) % len(tokens)] if next(stream) % 10 else next(stream) % 5001 * scale
        fields = dict(input_len=size, gas=gas, parse=("ok", token), keys=tokens, store=store,
                      count=5001 * scale if next(stream) % 20 else token + next(stream) % 2)
        if choice in (12, 13):
            tag = next(stream) % 256
            fields["parse"] = ("err", 0x0D if tag == 0x0C else tag)
        users = set()
        for _ in range(1 + next(stream) % 20):
            base = prefixes[next(stream) % 3] if next(stream) % 2 else bytes(next(stream) & 0xFF for _ in range(20))
            at = next(stream) % 20
            users.add(base[:at] + bytes([next(stream) & 0xFF]) + base[at + 1:])
        users = sorted(users)
        form, users = pick_form(stream, users)
        addr = users[next(stream) % len(users)] if users and next(stream) % 10 else prefixes[next(stream) % 3][:19] + bytes([next(stream) & 0xFF])
        fields.update(users=form, user_keys=users, addr=addr, cmp=("unit", "diff", "wide")[next(stream) % 3])
        mkeys = sorted({next(stream) % 5000 * scale for _ in range(next(stream) % 20)} | ({token} if next(stream) % 10 else set()))
        mform, mkeys = pick_form(stream, mkeys)
        if mform[0] == "tree" and token not in mkeys and next(stream) % 2 and len(mkeys) > 0:
            mkeys = sorted(set(mkeys[:-1]) | {token})
        fields.update(umap=mform, umap_keys=mkeys)
        small = next(stream) % 3
        if small:
            fields["value"] = (draw(stream), next(stream) % (10 ** 30) % (1 << 64), draw(stream), next(stream) % (10 ** 28) % (1 << 64))
            fields["rec"] = (E14 + next(stream) % (10 ** 13), E14 + next(stream) % (10 ** 13))
        else:
            fields["value"] = (draw(stream), draw(stream), draw(stream), draw(stream))
            fields["rec"] = (draw(stream), draw(stream))
        if next(stream) % 20 == 0:
            fields["once"] = 3
        twist = next(stream) % 40
        if twist == 0 and store[0] == "ring":
            fields["tok_answers"] = [(0, 0), (next(stream) % 3, next(stream) % 8), (next(stream) % 3, next(stream) % 8)]
        elif twist == 1:
            fields["faults"] = {next(stream) % 2: draw(stream) | (next(stream) % 3) << 64}
        elif twist == 2:
            fields["reply_len"] = draw(stream)
        elif twist == 3:
            fields["fail_alloc"] = next(stream) % 2
        yield Case("vector %d" % number, **fields)


# ----- controls -----

def first_failure(harness, cases):
    """For edited bytes: the first case whose run fails (the interpreter halts) or disagrees with the unchanged rule list, or None. The rule
    list itself is never allowed to raise here."""
    for case in cases:
        try:
            run = harness.run(case)
        except (Halt, EvidenceError, KeyError, IndexError, ValueError, OverflowError, struct.error):
            return case
        if judge(run, case) is not None:
            return case
    return None


def variant_counts(harnesses, cases):
    """For every wrong reading: how many cases give a real disagreement, and the first one. The bytes run once per case; an exception in the
    rule list is an error of the tool, never a detection."""
    counts = {name: [0, None, 0] for name in VARIANTS}
    for case in cases:
        run = harnesses[injected(case)].run(case)
        if judge(run, case) is not None:
            raise EvidenceError("unmodified rule list disagrees: %s" % case.name)
        for name in VARIANTS:
            try:
                difference = judge(run, case, frozenset((name,)))
            except Exception as error:  # noqa: BLE001 - reported, not counted
                raise EvidenceError("rule list raised under variant %s on %s: %r" % (name, case.name, error))
            if difference is not None:
                counts[name][0] += 1
                counts[name][1] = counts[name][1] or case.name
                if any(event[0] == "fault" for event in spec(case, run[0], frozenset((name,)))[2]):
                    counts[name][2] += 1  # the wrong reading addresses memory outside the fixture: a predicted fault
    return counts


# Survivors of the byte edits fall in two classes.
# EQUIVALENT: the edit provably cannot change any compared result. The changed bytes are either identical to the original, never read by
# the code that runs from its real bytes, or overwritten before such a read; and they lie outside every object whose pointer reaches a
# stubbed callee (the 0x58 byte parse result, the code structs at rsp+0x20, the out words at rsp+8/rsp+0xa8, the 8 byte keys, the 20 byte
# key, the bytes-constructor words), so no un-run callee is assumed about.
# STUB_DEPENDENT: the edit changes bytes (or a pointer) that reach an un-run, stubbed callee; it survives only because the stub reads
# fewer bytes than the edit changes. Each reason names the bytes and the callee that would have to read them.
HEIGHT_UNUSED = ("the edit changes only the height that 0x35bf460 (run from its bytes) uses: the height decides only whether the walk may "
                 "descend below a leaf, which happens only on a miss, and from this caller the walk always finds the token that the body's "
                 "identical inline walk found in the same tree; the height word written to the result (+0x10) is never read by 0x46df170")
THIRD_POINTER = "the closure's third word is never read by 0x46df170 (run from its bytes: it reads only closure+0 and closure+8)"
EQUIVALENT = {
    (0x38E5E75, "displacement"): ("movb %cl,0x20(%rsp) becomes movb %cl,0x28(%rsp): rsp+0x20 keeps the parser's tag byte, which is the "
                                  "value cl was loaded from with no write in between, and rsp+0x28 is overwritten by 0x38e5e87 on every path"),
    (0x38E5F25, "displacement"): ("movq %r12,0x128(%rsp) becomes movq %r12,0x120(%rsp): rsp+0x128 is reached only through the closure's third "
                                  "word, and " + THIRD_POINTER + "; rsp+0x120 is rewritten at 0x38e625d before its only read at 0x38e62e1"),
    (0x38E5FD5, "immediate"): ("the first immediate byte of the store to text+5 changes text byte 5, which the store of 'Invalid ' to "
                               "text+0..+7 at 0x38e5fed writes again"),
    (0x38E61F5, "displacement"): ("leaq 0x128(%rsp) becomes leaq 0x120(%rsp): only the closure's third word changes, and " + THIRD_POINTER),
    (0x38E61FD, "displacement"): ("movq %rax,0x18(%rsp) becomes movq %rax,0x10(%rsp): the closure's second word points to rsp+0x128 instead "
                                  "of rsp+0x98, and both hold the token (stored at 0x38e5f25 and 0x38e6099, nothing writes them before the "
                                  "call); 0x46df170 copies the key by value, so the pointer itself goes nowhere; " + THIRD_POINTER),
    (0x38E63A2, "immediate"): ("movq $-1,%rax becomes movq $-2,%rax on the multiply-overflow path: the first charge is at least 1000, so "
                               "adding 2^64-2 carries as adding 2^64-1 does, and the carry selects the 2^64-1 loaded at 0x38e634f"),
    (0x46DF1CC, "displacement"): "movq 0x68(%r14),%rdx becomes movq 0x60(%r14),%rdx (the nonzero root pointer as the height); " + HEIGHT_UNUSED,
    (0x46DF28C, "displacement"): "movq 0x68(%r14),%rdx becomes movq 0x60(%r14),%rdx (the nonzero root pointer as the height); " + HEIGHT_UNUSED,
    (0x35BF4AE, "immediate"): "subq $1,%r8 becomes subq $0,%r8 on the descend-at-index path: the height is not decremented; " + HEIGHT_UNUSED,
    (0x35BF4C6, "immediate"): "subq $1,%r8 becomes subq $0,%r8 on the descend-at-length path: the height is not decremented; " + HEIGHT_UNUSED,
    (0x35BF4DF, "displacement"): ("movq %rdx,0x10(%rax) becomes movq %rdx,0x18(%rax), which the next store of the index to +0x18 overwrites; "
                                  "+0x10 of the result (0x46df170's rsp+0x38) is never read by 0x46df170"),
}
CODE_FA = ("they live until 0x38e5f2d overwrites rsp+0x20..0x27; the only callees that see them are the token-count refusal's builder "
           "0x46de430 and drop 0x3d57b80, which receive rsp+0x20 (the u16 code 0xfa at +0, the token at +8); the stubs read only +0..+1 and "
           "+8..+15, so a builder or drop that read these padding bytes would see the change")
LATE = ("they live until 0x46df170 writes rsp+0x20..0x4f at 0x38e6214; callees that receive rsp+0x20 before that are 0x46de430, 0x3d57b80, "
        "slot 0x64e9570 (code structs) and 0x4556410 (8 byte key), and on the refused path 0x38f9750 (the 0x58 byte parse result)")
STUB_DEPENDENT = {
    (0x38E5E79, "displacement"): ("movb %r8b,0x27(%rsp) becomes movb %r8b,0x2f(%rsp) (overwritten at 0x38e5e87): on the accepted path "
                                  "rsp+0x27 keeps the parser's byte 7 instead of 0; " + CODE_FA),
    (0x38E5E7E, "displacement"): ("movw %di,0x25(%rsp) becomes movw %di,0x2d(%rsp) (overwritten at 0x38e5e87): on the accepted path "
                                  "rsp+0x25..0x26 keep the parser's bytes 5..6 instead of 0; " + CODE_FA),
    (0x38E5E83, "displacement"): ("movl %esi,0x21(%rsp) becomes movl %esi,0x29(%rsp) (overwritten at 0x38e5e87): on the accepted path "
                                  "rsp+0x22..0x24 keep the parser's bytes 2..4 instead of 0 (byte 1 is rewritten by the u16 code); " + CODE_FA),
    (0x38E5ED7, "displacement"): ("movl %edi,0x44(%rsp) becomes movl %edi,0x4c(%rsp) (overwritten at 0x38e5edb): on the accepted path "
                                  "rsp+0x44..0x47 keep the parser's bytes 0x24..0x27 (token bytes 4..7) instead of uninitialised stack copied "
                                  "through rsp+0xac; a callee would have to read offset 0x24..0x27 of the object at rsp+0x20; " + LATE),
    (0x38E5EEA, "displacement"): ("movl %r9d,0x70(%rsp) becomes movl %r9d,0x78(%rsp): rsp+0x70..0x73 keep the parser's bytes 0x50..0x53 "
                                  "(on the accepted path instead of uninitialised stack) and rsp+0x78..0x7b, just past the 0x58 byte "
                                  "result, receive them; a callee would have to read offset 0x50..0x5b of the object at rsp+0x20; " + LATE),
    (0x38E5EEF, "displacement"): ("movl %edx,0x74(%rsp) becomes movl %edx,0x7c(%rsp): rsp+0x74..0x77 keep the parser's bytes 0x54..0x57 "
                                  "(on the accepted path instead of uninitialised stack) and rsp+0x7c..0x7f, past the 0x58 byte result, "
                                  "receive them; a callee would have to read offset 0x54..0x5f of the object at rsp+0x20; " + LATE),
    (0x38E602C, "displacement"): ("leaq 0x20(%rsp),%rsi becomes leaq 0x28(%rsp),%rsi for the token-store ring search 0x4556410: the key "
                                  "pointer moves to rsp+0x28, which also holds the token (0x38e5e87), but the 8 bytes after it differ "
                                  "(the parse result's +8 word instead of the token copy); the stub reads only the 8 byte key, so a "
                                  "search that read more, or compared the pointer, would see the change"),
    (0x46DF267, "displacement"): ("movq %rax,0x8(%rsp) becomes movq %rax,0x0(%rsp) in 0x46df170: the second half's key store lands on "
                                  "rsp+0, which 0x46df170 never reads, and rsp+8 must still hold the first half's key (the same token); "
                                  "in the tree form 0x35bf460 runs from its bytes and does not write rsp+8, but in the ring form this rests "
                                  "on the stubbed 0x4556410 not writing through its key pointer"),
}


def edits_for(image, rows, seen):
    """One single-byte edit per reached instruction and form: branch/cmov/set condition, first immediate byte, displacement byte."""
    edits = []
    for row in rows:
        if row.va not in seen:
            continue
        data = bytes(image.blob[image.offset(row.va):image.offset(row.va) + row.size])
        if row.op == "jcc":
            at = row.size - 5 if row.size >= 6 else 0
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.op in ("cmov", "set"):
            at = next(index for index in range(row.size) if data[index] == 0x0F) + 1
            edits.append((row.va, "condition", {row.va + at: data[at] ^ 1}))
            continue
        if row.imm_at is not None and row.op not in ("call", "jmp"):
            edits.append((row.va, "immediate", {row.va + row.imm_at: data[row.imm_at] ^ 1}))
        at = displacement_at(row, data)
        if at is not None:
            edits.append((row.va, "displacement", {row.va + at: data[at] ^ 8}))
    return edits


def displacement_at(row, data):
    operand = row.a if row.a and row.a[0] == "m" else row.b if row.b and row.b[0] == "m" else None
    if operand is None or operand[5] or operand[1] is None or operand[4] == 0:
        return None
    end = row.size - (row.imm_size or 0)
    value = operand[4]
    if -128 <= value < 128 and data[end - 1] == value & 0xFF:
        return end - 1
    if data[end - 4:end] == struct.pack("<i", value):
        return end - 4
    return None


def run_mutants(image, rows_by_function, seen, cases):
    results = []
    plain = [case for case in cases if not injected(case)]
    forced = [case for case in cases if injected(case)]
    control = Harness(image)
    control.machine.step_limit = 20000
    if first_failure(control, cases) is not None:
        raise EvidenceError("the unedited bytes fail a kill case under the mutant step limit")
    for name in ("body", "pairs", "users", "tree_search"):
        for va, kind, patch in edits_for(image, rows_by_function[name], seen):
            harness = Harness(image, patch)
            harness.machine.step_limit = 20000
            if first_failure(harness, plain) is not None:
                results.append((name, va, kind, "killed", "by a consistent-fixture case"))
            elif first_failure(harness, forced) is not None:
                results.append((name, va, kind, "killed", "only by a case with injected answers"))
            elif (va, kind) in EQUIVALENT:
                results.append((name, va, kind, "equivalent", EQUIVALENT[(va, kind)]))
            elif (va, kind) in STUB_DEPENDENT:
                results.append((name, va, kind, "stub_dependent", STUB_DEPENDENT[(va, kind)]))
            else:
                results.append((name, va, kind, "survived", "UNEXPLAINED"))
    return results


def default_from_bytes(image):
    """Run the lazy init function 0x3714110 from its bytes into a marked buffer and return what it wrote, by offset."""
    machine = Machine(image)
    machine.memory.reset(0x1000)
    target = HEAP_BASE + 0x400
    machine.run(LAZY_INIT, {RDI: target})
    data = machine.memory.heap[0x400:0x400 + 0x38]
    return {offset: data[offset] for offset in range(0x38) if data[offset] != 0xA5}


def lazy_default_check(image):
    """Run 0x3714110 from its bytes and require that it writes exactly DEFAULT_WRITES; returns the written bytes as hex by offset order."""
    wrote = default_from_bytes(image)
    want = {}
    for offset, size, value in DEFAULT_WRITES:
        for index in range(size):
            want[offset + index] = (value >> (8 * index)) & 0xFF
    # bytes the init writes as 0xa5 would be hidden by the mark; none of the listed values contains 0xa5
    if wrote != want:
        raise EvidenceError("the lazy default in the rule list is not what 0x3714110 writes")
    return "".join("%02x" % wrote[offset] if offset in wrote else ".." for offset in range(0x38))


def structural_controls(image, harness, cases):
    """(kind, control, outcome) rows. Identification and target-byte controls feed wrong inputs to the tool's checks; comparator self-tests
    corrupt the expected side of one real comparison and require the comparator to report it."""
    rows = []
    blob = bytearray(image.blob)
    blob[1000] ^= 1
    with tempfile.TemporaryDirectory() as folder:
        path = pathlib.Path(folder) / "hl-node"
        path.write_bytes(bytes(blob))
        try:
            load_image(path)
            outcome = "MISSED"
        except EvidenceError:
            outcome = "detected"
    rows.append(("identification", "the digest gate (load_image) refuses the binary with one flipped byte", outcome))
    for label, va in (("address inside the body", ENTRY + 1), ("address before the body", ENTRY - 1), ("the first landing pad", BODY_END),
                      ("address in .rodata", 0x459090), ("address past the file", 0x7FFFFFFFFF)):
        try:
            image.exact_fde(va)
            rows.append(("identification", label + " is refused as a function start", "MISSED"))
        except EvidenceError:
            rows.append(("identification", label + " is refused as a function start", "detected"))
    relative = image.relative()
    rows.append(("identification", "table slot of the 0x...0812 neighbour does not hold the body",
                 "detected" if relative.get(TABLE_SLOT + 0x20) != ENTRY else "MISSED"))
    rows.append(("identification", "table slot of the 0x...0810 neighbour does not hold the body",
                 "detected" if relative.get(TABLE_SLOT - 0x20) != ENTRY else "MISSED"))
    probe = next(case for case in cases if case.name == "first half: index 1.5")
    run = harness.run(probe)
    if judge(run, probe) is not None:
        raise EvidenceError("probe disagrees")
    other = Case("other field", value=probe.value, rec=(probe.rec[0] + 1, probe.rec[1]))
    out, writes, _, _, _ = spec(other, Layout(other))
    rows.append(("target bytes", "the heap after a run with one record field compared with the rule list's heap for that field plus one",
                 "detected" if run[2] != expected_heap(run[1], out, writes) else "MISSED"))
    lazy = Case("lazy probe", user_keys=[], once=3)
    rows.append(("target bytes", "missing key with once state 3 judged against a rule list that skips the once",
                 "detected" if judge(harness.run(lazy), lazy, frozenset(("once_skip",))) is not None else "MISSED"))

    def flip(offset):
        def tamper(events, heap, statics, state):
            data = bytearray(heap)
            data[offset - HEAP_BASE] ^= 1
            return events, bytes(data), statics, state
        return tamper

    def drop_one_divide(events, heap, statics, state):
        at = next(index for index, event in enumerate(events) if event[0] == "div")
        if sum(1 for event in events if event[0] == "div") != 2:
            raise EvidenceError("probe should make two divides")
        return events[:at] + events[at + 1:], heap, statics, state

    def other_state(events, heap, statics, state):
        return events, heap, statics, state ^ 1

    for label, tamper in (("one flipped bit in the expected reply bytes", flip(ALLOCS + 0x3F)),
                          ("one flipped bit in the expected store bytes", flip(POOL + 0x40)),
                          ("exactly one of the two divide requests removed from the expected events", drop_one_divide),
                          ("the expected once state changed", other_state)):
        rows.append(("comparator self-test", label, "detected" if judge(run, probe, tamper=tamper) is not None else "MISSED"))
    return rows


def table_rows(image):
    relative = image.relative()
    if relative.get(TABLE_SLOT) != ENTRY:
        raise EvidenceError("table slot does not hold the body")
    rows = []
    for slot in (TABLE_SLOT - 0x20, TABLE_SLOT, TABLE_SLOT + 0x20):
        address = bytes(image.blob[image.offset(slot - 0x18):image.offset(slot - 0x18) + 20])
        rows.append(("%#x" % slot, address.hex(), "%#x" % relative[slot]))
    if rows[1][1] != "00" * 18 + "0811":
        raise EvidenceError("table address bytes")
    return rows


def dynamic_symbol(image, index):
    table, names = image.named[".dynsym"], image.named[".dynstr"]
    name = struct.unpack_from("<I", image.blob, table["offset"] + 24 * index)[0]
    start = names["offset"] + name
    return bytes(image.blob[start:image.blob.index(b"\0", start)]).decode()


def slot_rows(image):
    relative = image.relative()
    rows = []
    for slot, target in sorted(SLOT_TARGETS.items()):
        if relative.get(slot) != target:
            raise EvidenceError("slot does not hold the target: %#x" % slot)
        rows.append(("%#x" % slot, "R_X86_64_RELATIVE", "%#x" % target))
    glob = [(kind, symbol) for at, kind, _, symbol in image.relocations() if at == SLOT_MEMCMP]
    if glob != [(6, glob[0][1])] or dynamic_symbol(image, glob[0][1]) != "memcmp":
        raise EvidenceError("memcmp slot")
    rows.append(("%#x" % SLOT_MEMCMP, "R_X86_64_GLOB_DAT", dynamic_symbol(image, glob[0][1])))
    if relative.get(LAZY) != LAZY_INIT:
        raise EvidenceError("lazy static does not start with its init function")
    rows.append(("%#x" % LAZY, "R_X86_64_RELATIVE (lazy value, before init)", "%#x" % LAZY_INIT))
    state = struct.unpack_from("<I", image.blob, image.offset(LAZY_STATE))[0]
    if state != LAZY_FILE_STATE:
        raise EvidenceError("lazy state in the file")
    rows.append(("%#x" % LAZY_STATE, "file word (once state)", str(state)))
    return rows


def site_rows(rows_by_function):
    sites = []
    for name, rows in rows_by_function.items():
        for row in rows:
            if row.op == "call":
                sites.append((name, "%#x" % row.va, "direct", "%#x" % row.target))
            elif row.op == "calli":
                operand = row.a
                if operand[0] == "m" and operand[1] is None and operand[2] is None and row.rip_at is not None:
                    sites.append((name, "%#x" % row.va, "slot", "%#x" % operand[4]))
                else:
                    sites.append((name, "%#x" % row.va, "register or memory", "-"))
    return sites


CONSTANTS = {SLOT_MEMCMP: "memcmp slot loaded into a register", LAZY_STATE: "lazy once state", LAZY: "lazy value",
             ONCE_VTABLE: "once closure vtable", ONCE_LOCATION: "once caller location"}


def constant_rows(image, rows_by_function):
    out, seen = [], set()
    for name, rows in rows_by_function.items():
        for row in rows:
            for operand in (row.a, row.b):
                if operand and operand[0] == "m" and row.rip_at is not None and operand[1] is None and operand[2] is None and row.op != "calli":
                    va = operand[4]
                    if (name, va) in seen:
                        continue
                    seen.add((name, va))
                    if va not in CONSTANTS:
                        raise EvidenceError("unlisted rip operand %#x" % va)
                    out.append((name, "%#x" % row.va, "rip %s" % row.op, "%#x" % va, CONSTANTS[va]))
            if row.op == "mov" and row.size >= 10 and row.data[0] & 0xF8 == 0x48 and 0xB8 <= row.data[1] <= 0xBF:
                value = struct.unpack_from("<Q", row.data, 2)[0]
                role = {OUT_OF_GAS: "out-of-gas word; minus 1 it is the B-tree form tag", BTREE_TAG: "B-tree form tag",
                        E14: "1e14 divisor and guard", 0x7475706E69206469: "text bytes 5..12 'id input'",
                        0x2064696C61766E49: "text bytes 0..7 'Invalid '"}.get(value)
                if role is None:
                    raise EvidenceError("unlisted movabs %#x" % value)
                out.append((name, "%#x" % row.va, "movabs", "%#x" % value, role))
    return out


def sample_rows(harness):
    rows = []
    for label, value, rec in (("index 1.0 both", (5, 7 * E14, 9, 11 * E14), (E14, E14)), ("index 1.25 and 2", (5, 8 * E14, 9, 3 * E14), (125 * 10 ** 12, 2 * E14)),
                              ("rounds down", (1, 3, 2, 999), (E14 // 3, E14 - 1)), ("first guard trips", (1, TOP, 2, 5), (TOP, E14)),
                              ("second guard trips", (1, 5, 2, TOP), (E14, TOP)), ("zero value", (0, 0, 0, 0), (E14, E14))):
        case = Case(label, value=value, rec=rec)
        layout, before, after, events, _, panicked = harness.run(case)
        reply = after[ALLOCS - HEAP_BASE:ALLOCS - HEAP_BASE + REPLY_SIZE]
        words = [int.from_bytes(reply[index * 32:index * 32 + 32], "big") for index in range(4)]
        rows.append((label,) + tuple(value) + tuple(rec) + tuple(words))
    return rows


RUST_HEADER = """# rust-vectors.tsv: inputs and outputs of the pure arithmetic of 0x38e5d00 / 0x46df170, every row taken from a run of the target bytes.
# Rows come from cases with consistent fixtures (no injected search answers, quotients, allocation failures or unusual once states), with
# one exception: rows of kind gas_reply_len use an injected answer of the bytes-constructor stub, a reported reply length other than 0x80
# (the real constructor reports the 0x80 it is given). They are kept because the gas charge reads that reported length.
# columns:
#  kind          named case group or "vector"
#  input_len     input length in bytes (u64)
#  gas_limit     the limit passed in r8 (u64)
#  reply_len     the reply length the bytes object reports (u64)
#  parse_ok      1 when the parser tag was 0x0c, else 0
#  token         parsed token index (u64; - when parse_ok is 0)
#  count         the token count at [[ctx+0x10]+0x38] (u64)
#  token_found   1 when the token store holds the token
#  entry_found   1 when the key's value exists and its map holds the token
#  v0 v8 v10 v18 the four u64 of the 32 byte map value (+0, +8, +0x10, +0x18)
#  f58 f78       the token record's u64 at +0x58 and +0x78
#  outcome       out_of_gas | invalid_input | code_fa | code_f1 | reply   (refusals before the reply leave words as -)
#  total_gas     out word 4 on a reply: sat(1000 + 33*input_len + sat(33*reply_len))
#  w0 w1 w2 w3   the four reply words (decimal u64; each is the last 8 bytes of a 32 byte big-endian word)
#  reply_hex     the 128 reply bytes in hex (- unless outcome is reply)
"""
RUST_COLUMNS = ("kind", "input_len", "gas_limit", "reply_len", "parse_ok", "token", "count", "token_found", "entry_found", "v0", "v8", "v10", "v18",
                "f58", "f78", "outcome", "total_gas", "w0", "w1", "w2", "w3", "reply_hex")


def rust_vectors(harness, vectors=250):
    rows = []
    groups = ("input length", "gas ", "first charge", "whole charge", "parse refused with", "first half", "second half", "both halves",
              "plain words", "reported reply length", "empty map", "lazy state", "token whose")
    groups += tuple("token %d against" % value for value in (0, 5, 7, 8, TOP - 1, TOP))
    pool = [case for case in named_cases() if case.name.startswith(groups)] + list(vector_cases(vectors, seed=0xB0B0811))
    for case in pool:
        if set(injected_kinds(case)) - {"reply length"}:
            continue
        layout, before, after, events, _, panicked = harness.run(case)
        form, words = classify(after, events, panicked)
        ok = case.parse[0] == "ok"
        token = case.token() if ok else None
        token_found = ok and token in case.keys and case.store[0] != "none"
        value_at = layout.user_at.get(case.addr) if case.users[0] != "none" else None
        entry_found = ok and value_at is not None and token in case.umap_keys and case.umap[0] != "none"
        value = case.value if entry_found else (0, 0, 0, 0)
        rec = case.rec if token_found else (0, 0)
        outcome = {"out of gas": "out_of_gas", "invalid input": "invalid_input", "reply": "reply"}.get(form)
        if outcome is None:
            outcome = "code_fa" if form.startswith("code 0xfa") else "code_f1"
        reply = after[ALLOCS - HEAP_BASE:ALLOCS - HEAP_BASE + REPLY_SIZE] if outcome == "reply" else b""
        kind = "gas_reply_len" if case.reply_len != REPLY_SIZE else "vector" if case.name.startswith("vector") else case.name.split(":")[0].split(",")[0]
        result = [str(int.from_bytes(reply[i * 32:i * 32 + 32], "big")) for i in range(4)] if reply else ["-"] * 4
        rows.append([kind.replace("\t", " "), case.input_len, case.gas, case.reply_len, int(ok), token if ok else "-", case.count, int(token_found),
                     int(entry_found)] + list(value) + list(rec) + [outcome, words[4] if reply else "-"] + result + [reply.hex() if reply else "-"])
    return rows


def analyse(image, vectors=12000, mutate=True):
    harnesses = {False: Harness(image), True: Harness(image)}  # split only so coverage can tell injected-only rows apart
    harness = harnesses[False]
    cases = named_cases()
    names = [case.name for case in cases]
    if len(set(names)) != len(names):
        raise EvidenceError("duplicate case name: %s" % sorted(name for name in names if names.count(name) > 1)[:3])
    outcomes = []
    for case in cases:
        difference = compare(harnesses[injected(case)], case)
        if difference:
            raise EvidenceError("case disagrees with the rule list: %s: %s" % (case.name, difference))
        outcomes.append(digest_row(harnesses[injected(case)], case))
    vector_rows, vector_count, injected_count = [], 0, 0
    for case in vector_cases(vectors):
        difference = compare(harnesses[injected(case)], case)
        if difference:
            raise EvidenceError("vector disagrees with the rule list: %s: %s" % (case.name, difference))
        if vector_count % 10 == 0:
            vector_rows.append(digest_row(harnesses[injected(case)], case))
        vector_count += 1
        injected_count += injected(case)
    seen_plain = set(harnesses[False].machine.seen)
    seen_all = seen_plain | set(harnesses[True].machine.seen)
    rows_by_function = {name: decode_range(image, start, end) for start, end, name in FUNCTIONS}
    unreached, injected_only = [], []
    for name, rows in rows_by_function.items():
        for row in rows:
            if row.op in ("int3", "nop"):
                continue
            if row.va not in seen_all:
                unreached.append((name, row.va, row.op))
            elif row.va not in seen_plain:
                injected_only.append((name, row.va, row.op))
    sample = cases + list(vector_cases(400, seed=0x77))
    counts = variant_counts(harnesses, sample)
    variants = [(name, "detected" if counts[name][0] else "MISSED", counts[name][0], counts[name][2], counts[name][1] or "-") for name in VARIANTS]
    result = dict(rows=rows_by_function, cases=cases, outcomes=outcomes, vector_rows=vector_rows, vector_count=vector_count,
                  injected_vectors=injected_count, named_injected=sum(1 for case in cases if injected(case)), unreached=unreached,
                  injected_only=injected_only, variants=variants, structural=structural_controls(image, harness, cases), table=table_rows(image),
                  slots=slot_rows(image), sites=site_rows(rows_by_function), constants=constant_rows(image, rows_by_function),
                  samples=sample_rows(harness), rust=rust_vectors(harness), fde=image.exact_fde(ENTRY), lazy_default=lazy_default_check(image),
                  variant_sample=len(sample))
    if mutate:
        kill = cases + list(vector_cases(80, seed=0x99))
        result["mutations"] = run_mutants(image, rows_by_function, seen_all, kill)
        unexplained = [row for row in result["mutations"] if row[4] == "UNEXPLAINED"]
        if unexplained:
            raise EvidenceError("unexplained survivors: %s" % [(row[0], hex(row[1]), row[2]) for row in unexplained])
    return result


UNREACHED_REASON = {
    0x38E63DB: "ud2 after the third allocation-error call; the allocation-error slot never returns",
}
TREE_MISS = ("miss exit of 0x35bf460: from this caller it searches the same token in the same B-tree that the body's inline walk "
             "(same comparison and descent) already found it in, so it cannot miss")
UNREACHED_REASON.update({0x35BF4B4: TREE_MISS, 0x35BF4EB: TREE_MISS, 0x35BF4F0: TREE_MISS})


def render(result):
    files = {}

    def tsv(name, header, rows, preamble=""):
        files[name] = preamble + "\n".join(["\t".join(header)] + ["\t".join(str(cell) for cell in row) for row in rows]) + "\n"

    rows = result["rows"]
    tsv("function-rows.tsv", ("function", "address", "size", "bytes", "operation"),
        [(name, "%#x" % row.va, row.size, row.data.hex(), row.op) for name in ("body", "pairs", "users", "tree_search") for row in rows[name]])
    tsv("table-entries.tsv", ("slot", "address_bytes", "callback"), result["table"])
    tsv("slots.tsv", ("slot", "form", "target"), result["slots"])
    tsv("call-sites.tsv", ("function", "site", "form", "target_or_slot"), result["sites"])
    tsv("constants.tsv", ("function", "row", "form", "value_or_address", "role"), result["constants"])
    tsv("reply-samples.tsv", ("case", "v0", "v8", "v10", "v18", "f58", "f78", "word0", "word1", "word2", "word3"), result["samples"])
    header = ("case", "form", "gas", "heap_digest", "reply", "divides", "events")
    tsv("outcomes.tsv", header, result["outcomes"])
    tsv("vector-outcomes.tsv", header, result["vector_rows"])
    tsv("model-variants.tsv", ("switch", "outcome", "disagreeing_cases_of_%d" % result["variant_sample"], "of_which_predicted_fault", "first_case"),
        result["variants"])
    tsv("structural-controls.tsv", ("kind", "control", "outcome"), result["structural"])
    unreached_rows = [("not reached by any case", name, "%#x" % va, op, UNREACHED_REASON.get(va, "UNEXPLAINED")) for name, va, op in result["unreached"]]
    unreached_rows += [("reached only with injected answers", name, "%#x" % va, op, "-") for name, va, op in result["injected_only"]]
    if any(row[4] == "UNEXPLAINED" for row in unreached_rows):
        raise EvidenceError("unexplained unreached rows: %s" % [row[2] for row in unreached_rows if row[4] == "UNEXPLAINED"])
    tsv("unreached-rows.tsv", ("class", "function", "address", "operation", "reason"), unreached_rows)
    tsv("rust-vectors.tsv", RUST_COLUMNS, result["rust"], RUST_HEADER)
    mutations = result.get("mutations", [])
    if mutations:
        tsv("mutations.tsv", ("function", "address", "kind", "outcome", "detail"),
            [(name, "%#x" % va, kind, outcome, detail) for name, va, kind, outcome, detail in mutations])
    killed = sum(1 for row in mutations if row[3] == "killed")
    equivalent = sum(1 for row in mutations if row[3] == "equivalent")
    stub_dependent = sum(1 for row in mutations if row[3] == "stub_dependent")
    if killed + equivalent + stub_dependent != len(mutations):
        raise EvidenceError("unclassified byte edit")
    variants_detected = sum(1 for row in result["variants"] if row[1] == "detected")
    controls = [row for row in result["structural"] if row[0] != "comparator self-test"]
    self_tests = [row for row in result["structural"] if row[0] == "comparator self-test"]
    structural_detected = sum(1 for row in controls if row[2] == "detected")
    self_tests_detected = sum(1 for row in self_tests if row[2] == "detected")
    if variants_detected != len(result["variants"]) or structural_detected != len(controls) or self_tests_detected != len(self_tests):
        raise EvidenceError("a negative control was missed: %s" % [row for row in result["variants"] + result["structural"] if "MISSED" in row])
    start, end = result["fde"]
    summary = {
        "binary": "artifacts/node/115/hl-node", "sha256": SHA256,
        "function": {"address": "%#x" % start, "fde_end": "%#x" % end, "fde_bytes": end - start, "body_end": "%#x" % BODY_END, "body_bytes": BODY_END - start,
                     "body_instructions": len(rows["body"]), "landing_pad_bytes_not_run": end - BODY_END},
        "real_callees": {name: {"address": "%#x" % s, "end": "%#x" % e, "instructions": len(rows[name])} for s, e, name in FUNCTIONS if name != "body"},
        "table": {"slot": "%#x" % TABLE_SLOT, "address_bytes": result["table"][1][1]},
        "named_cases": len(result["cases"]), "named_cases_with_injected_answers": result["named_injected"],
        "vector_cases": result["vector_count"], "vector_cases_with_injected_answers": result["injected_vectors"],
        "rows_not_reached": ["%s %#x" % (name, va) for name, va, _ in result["unreached"]],
        "rows_reached_only_with_injected_answers": ["%s %#x" % (name, va) for name, va, _ in result["injected_only"]],
        "model_variants": len(result["variants"]), "model_variant_sample_cases": result["variant_sample"],
        "structural_controls": len(controls), "comparator_self_tests": len(self_tests), "rust_vectors": len(result["rust"]),
        "rust_vectors_with_injected_reply_length": sum(1 for row in result["rust"] if row[0] == "gas_reply_len"),
        "lazy_default_written_by_0x3714110": result["lazy_default"], "mismatches": 0,
        "injected_case_kinds": ["search answers", "quotients", "reply length", "allocation failure", "once state other than 0 or 3"],
    }
    measure = {"cases": len(result["cases"]) + result["vector_count"], "mismatches": 0, "variants": len(result["variants"]),
               "variants_detected": variants_detected, "structural_controls": len(controls), "structural_detected": structural_detected,
               "comparator_self_tests": len(self_tests), "comparator_self_tests_detected": self_tests_detected}
    if mutations:
        summary["mutations"] = {"total": len(mutations), "killed": killed, "equivalent": equivalent, "stub_dependent": stub_dependent,
                                "killed_only_with_injected_answers": sum(1 for row in mutations if row[4] == "only by a case with injected answers"),
                                "by_function": {name: sum(1 for row in mutations if row[0] == name) for name in ("body", "pairs", "users", "tree_search")}}
        measure.update({"byte_edits": len(mutations), "byte_edits_killed": killed, "byte_edits_equivalent": equivalent,
                        "byte_edits_stub_dependent": stub_dependent})
    files["evidence.json"] = json.dumps(summary, indent=1, sort_keys=True) + "\n"
    files["measure.json"] = json.dumps(measure, indent=1, sort_keys=True) + "\n"
    return files


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out", required=True, type=pathlib.Path)
    parser.add_argument("--vectors", type=int, default=12000)
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
