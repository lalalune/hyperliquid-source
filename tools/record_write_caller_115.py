"""Python model of the node #115 record-write caller.

Pinned from the node #115 binary (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301):
the record-write caller 0x5fc6070..0x5fc6e8b, its sibling record
write 0x5f0f3d0..0x5f0f8c1, the validator 0x5fb9a10..0x5fb9bcb, the
hashmap find-or-insert 0x5fc5e30..0x5fc5fdf with its rehash
0x5fc5cf0..0x5fc5e2d, the map lower_bound 0x5fb7040..0x5fb70d2,
the hash combine 0x5fb70e0..0x5fb7131, the Status move-assign
0x5fb71b0..0x5fb7219, the produce-request init
0x60b21f0..0x60b2262, the strdup helper 0x61cf610..0x61cf64f,
the no-op stub 0x5d54f00..0x5d54f05, the closed-path delegate
0x5fbed30..0x5fbf077 with its counter getter/setter, vector
grow and finalizer, the min-register 0x5f0a1a0..0x5f0a1d0, and
the post-write hook 0x5fb6a60..0x5fb6bbf. The record-write
entry 0x5f0f930, the record insert 0x5f0e890, the varint32
encoder 0x61bd410 and the Status builder 0x61cf670 are pinned
by the #3337/#3330 packets and are injected here as callables;
the 64-bit hash 0x61c3530, the duplicate-detector check
0x5fbe340 and the virtual produce slots are contract-only and
are likewise injected.

Every branch condition below was read off the disassembly with
the AT&T operand order in mind (`cmp src,dst` subtracts src
from dst, so `cmp mem,reg; jb` jumps when reg < mem). The
three magnitude gates that decide the fallback, the sibling
update and the fallback finalizer are therefore: a length
above 0xffffffff is "too large"; an in-place update happens
only when the new value fits (new length <= stored length);
the fallback rolls back only when the built key exceeds the
+0x28 maximum length (a zero maximum disables the check).
"""

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

SNAPSHOT_VTABLE = 0x64C92D0
SNAPSHOT_TYPEINFO = 0x96CE30
SNAPSHOT_TYPEINFO_PTR = 0x64C9158
SNAPSHOT_VTABLE_SLOTS = (0x5D484B0, 0x5D484C0, 0x5D484D0, 0x5D54F10, 0x5D54F30)

HASH_SEED = 0xD28AAD72F49BD50B
SIBLING_FOLD_SEED = 0x77A00858DDD37F21
FALLBACK_HASH_SEEDS = (0x0, 0xD28AAD72F49BD50B, 0xA5155AE5E937AA16, 0x4A2AB5CBD26F542C)

CANONICAL_PRODUCT1 = 0x5F04D80
CANONICAL_PRODUCT2 = 0x5D2CA80

VALIDATOR_BAD_CF = "Invalid column family specified in write batch"
FALLBACK_KEY_TOO_LARGE = "key is too large"
FALLBACK_VALUE_TOO_LARGE = "value is too large"
STRING_APPEND_OVERFLOW = "basic_string::append"

U32_MAX = 0xFFFFFFFF
ABORTED_MEMORY_LIMIT = 0x70A  # code byte 0x0a (kAborted), subcode byte 0x07


class Status:
    """A 16-byte Status {+0 u32 code, +4 u16 code2, +8 msg ptr}."""

    def __init__(self, code=0, code2=0, msg=None):
        self.code = code
        self.code2 = code2
        self.msg = msg

    def __eq__(self, other):
        return (isinstance(other, Status) and self.code == other.code
                and self.code2 == other.code2 and self.msg == other.msg)

    def __repr__(self):
        return "Status(%#x, %#x, %r)" % (self.code, self.code2, self.msg)


def empty_status():
    return Status(0, 0, None)


def status_move(dst, src):
    """Status move-assign 0x5fb71b0: copy the 6 header bytes and
    the message pointer, zero the source, delete[] the
    destination's old message (modelled as dropping it)."""
    dst.code, dst.code2, dst.msg = src.code, src.code2, src.msg
    src.code, src.code2, src.msg = 0, 0, None
    return dst


def status_build(code, msg):
    """Status builder 0x61cf670: Status{code, code2=0, msg}."""
    return Status(code, 0, msg)


def varint_encode(value):
    """Varint32 encoder 0x61bd410: unsigned LEB128, 7 bits per byte."""
    out = bytearray()
    value &= U32_MAX
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def varint_decode(buf, pos=0):
    """Varint decoder 0x61bd4f0: returns (value, next_pos). The
    short form is a single byte; the long form is LEB128."""
    if buf[pos] & 0x80:
        value = 0
        shift = 0
        while True:
            byte = buf[pos]
            pos += 1
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                break
            shift += 7
        return value, pos
    return buf[pos], pos + 1


# Produce-request init 0x60b21f0 (0x90 bytes), as built by the
# caller on the code-1 path: the +0x2c qword is 0x101 as
# initialised and 0x001 after the caller clears its 0x2d byte.
PRODUCE_REQUEST = {
    0x00: 0, 0x08: 0, 0x10: 0, 0x18: 0, 0x20: 0, 0x28: 0,
    0x2C: 0x001, 0x34: 0, 0x38: 0, 0x48: 0, 0x50: 0, 0x58: 0,
    0x68: 0, 0x78: -1, 0x80: 0, 0x84: 4, 0x88: 0x100,
}


def produce_request_init():
    """Produce-request init 0x60b21f0 plus the caller's +0x2c fix."""
    return dict(PRODUCE_REQUEST)


def strdup_into(slot, value):
    """Strdup helper 0x61cf610: allocate a copy of the string and
    store its pointer in slot[0]; returns the slot."""
    slot[0] = bytes(value) if isinstance(value, (bytes, bytearray)) else value
    return slot


def hash_combine(out, a_data, a_len, b_data, b_len, hash64, seed=HASH_SEED):
    """Hash combine 0x5fb70e0: *out ^= H(seed, a) ^ H(seed, b).
    H is the contract-only 64-bit hash 0x61c3530, injected.
    The combine itself always uses HASH_SEED; the sibling
    fold passes SIBLING_FOLD_SEED."""
    out[0] ^= hash64(a_data, a_len, seed) ^ hash64(b_data, b_len, seed)


def _next_prime(n):
    p = n
    while True:
        if p > 1 and all(p % d for d in range(2, int(p ** 0.5) + 1)):
            return p
        p += 1


class HashMap:
    """The unordered_map at owner+0x110 keyed by handle pointer:
    0x18-byte nodes {next +0x00, key +0x08, value +0x10}."""

    def __init__(self):
        self.buckets = [[]]
        self.count = 1
        self.size = 0
        self.load_factor = 1.0

    def __repr__(self):
        return "HashMap(buckets=%d, size=%d)" % (self.count, self.size)


def hashmap_rehash(table):
    """Rehash 0x5fc5cf0: a new bucket array, nodes reinserted by
    key % new_count. The new count follows the libstdc++
    _Prime_rehash_policy growth (next prime at or above twice
    the old count); the exact prime list is not pinned, only
    the growth and the reinsertion."""
    new_count = _next_prime(2 * table.count)
    new_buckets = [[] for _ in range(new_count)]
    for chain in table.buckets:
        for node in chain:
            new_buckets[node["key"] % new_count].append(node)
    table.buckets = new_buckets
    table.count = new_count


def hashmap_find_or_insert(table, key):
    """Hashmap find-or-insert 0x5fc5e30: returns the value cell
    (a one-element list) of the node for key, creating a node
    with value 0 when absent; rehashes when the load would
    exceed the 1.0 load factor."""
    idx = key % table.count
    for node in table.buckets[idx]:
        if node["key"] == key:
            return node["value_cell"]
    if table.size + 1 > table.count:
        hashmap_rehash(table)
        idx = key % table.count
    node = {"key": key, "value_cell": [0]}
    table.buckets[idx].append(node)
    table.size += 1
    return node["value_cell"]


class RbMap:
    """The std::map at owner+0x70: 0x40-byte nodes, key at +0x20,
    value at +0x28."""

    def __init__(self):
        self.entries = {}

    def __repr__(self):
        return "RbMap(%d entries)" % len(self.entries)


def map_lower_bound(tree, key):
    """Map lower_bound 0x5fb7040: returns (node or None, hint key
    or None) where the hint is the first key >= the searched
    key (the node the insert would attach to)."""
    for k in sorted(tree.entries):
        if k >= key:
            return (tree.entries[k] if k == key else None, k)
    return (None, None)


def map_insert(tree, key):
    """The inline map insert: returns the existing node when the
    key is present, else allocates a 0x40-byte node with the key
    at +0x20 and inserts it."""
    if key in tree.entries:
        return tree.entries[key]
    node = {"key": key, "value": 0}
    tree.entries[key] = node
    return node


def register_min(handle, value):
    """Min-register 0x5f0a1a0: *(handle+0xc38) = min(current,
    value), with 0 treated as unset, via a lock-CAS loop."""
    current = handle.get("reg_c38", 0)
    if current == 0 or value < current:
        handle["reg_c38"] = value


def validate(owner, out, slots):
    """Validator 0x5fb9a10: (owner, arg3, &Status) -> bool.
    slots: slot10() -> bool, slot18() -> int, slot20() ->
    handle, register(handle, value) -> None."""
    if not slots["slot10"]():
        if owner.get("f28"):
            out.code, out.code2, out.msg = 0, 0, None
        else:
            out.code, out.code2, out.msg = 4, 0, VALIDATOR_BAD_CF
        return False
    if owner.get("f30"):
        if owner["f30"] < slots["slot18"]():
            out.code, out.code2, out.msg = 0, 0, None
            return False
    if owner.get("f60") is not None:
        owner["f60"][0] = 1
    if owner.get("f38"):
        handle = slots["slot20"]()
        slots["register"](handle, owner["f38"])
    return True


def fallback(out, obj, arg3, arg4, arg5, hash64):
    """Closed-path delegate 0x5fbed30 with its finalizer
    0x5fbebc0. arg4/arg5 are {"data": bytes, "len8": int};
    obj is {"key": bytearray, "key_size": int, "flags": int,
    "klen28": int, "hashes": list, "hash_slack": int} where
    key_size is the key string's size (the counter the
    0x5fbb000 getter reads at *(key+8)) and hashes is the
    vector at obj+0x30. The key string is a pointer to a
    std::string, so the setter bumps its size by 1 before the
    leading-byte append: the byte at the old size index is
    whatever the buffer held (a stale byte)."""
    if arg4["len8"] > U32_MAX:
        out.code, out.code2, out.msg = 4, 0, FALLBACK_KEY_TOO_LARGE
        return out
    if arg5["len8"] > U32_MAX:
        out.code, out.code2, out.msg = 4, 0, FALLBACK_VALUE_TOO_LARGE
        return out
    before = obj["key_size"]
    flags_before = obj["flags"]
    obj["key_size"] = before + 1
    key = obj["key"]
    if arg3 != 0:
        _key_set(key, obj["key_size"], 5)
        obj["key_size"] += 1
        key[obj["key_size"]:obj["key_size"]] = varint_encode(arg3)
        obj["key_size"] += len(varint_encode(arg3))
    else:
        _key_set(key, obj["key_size"], 1)
        obj["key_size"] += 1
    key[obj["key_size"]:obj["key_size"]] = varint_encode(arg4["len8"] & U32_MAX)
    obj["key_size"] += len(varint_encode(arg4["len8"] & U32_MAX))
    key[obj["key_size"]:obj["key_size"]] = arg4["data"]
    obj["key_size"] += len(arg4["data"])
    key[obj["key_size"]:obj["key_size"]] = varint_encode(arg5["len8"] & U32_MAX)
    obj["key_size"] += len(varint_encode(arg5["len8"] & U32_MAX))
    key[obj["key_size"]:obj["key_size"]] = arg5["data"]
    obj["key_size"] += len(arg5["data"])
    obj["flags"] |= 2
    # Four-way hash fold over (arg4 bytes, arg5 bytes, the
    # 1-byte 0x01, arg3 as u32) with the pinned seeds.
    folded = hash64(arg4["data"], len(arg4["data"]), FALLBACK_HASH_SEEDS[0])
    folded ^= hash64(arg5["data"], len(arg5["data"]), FALLBACK_HASH_SEEDS[1])
    folded ^= hash64(b"\x01", 1, FALLBACK_HASH_SEEDS[2])
    folded ^= hash64(arg3.to_bytes(4, "little"), 4, FALLBACK_HASH_SEEDS[3])
    obj["hashes"].append(folded)
    # Finalizer 0x5fbebc0: a zero +0x28 maximum disables the
    # check; a built key longer than the maximum rolls the
    # append back and reports Aborted(MemoryLimit).
    if obj["klen28"] != 0 and obj["key_size"] > obj["klen28"]:
        obj["key_size"] = before
        if len(obj["hashes"]) > before:
            obj["hashes"] = obj["hashes"][:before]
        else:
            obj["hash_slack"] = before - len(obj["hashes"])
        obj["flags"] = flags_before
        out.code, out.code2, out.msg = ABORTED_MEMORY_LIMIT, 0, None
        return out
    out.code, out.code2, out.msg = 0, 0, None
    return out


def _key_set(key, pos, byte):
    """Write one byte into the key buffer at pos, extending the
    buffer with zeroes when the position is past its end (the
    buffer retains stale bytes past the string's size)."""
    while len(key) <= pos:
        key.append(0)
    key[pos] = byte


def sibling_write(out, handle, tag, direct, key, value, arg7, slots):
    """Sibling record write 0x5f0f3d0..0x5f0f8c1. key/value are
    {"data": bytes, "len8": int} slices; the record layout is
    varint(length) + payload (last 8 bytes = trailer) +
    varint(value length) + value bytes. slots: key_build(key,
    tag) -> bytes; product1_slot90() / product1_slot98() ->
    object; product1_slot10(obj, key) -> bool;
    product1_slot18(obj) -> bytes (the found record);
    product2_slot10(obj, key) / product2_slot98(obj, key) ->
    bool; value_length(record, pos) -> int; bucket(handle,
    key) -> int; wrlock(b) / unlock(b); notify(obj, a, b);
    hash64(data, length, seed) -> int; resolve(handle, fold,
    key, value, value_end, typ, hi); validate(out, handle,
    record, trailer_hi, value, value_end); insert(out,
    handle, tag, direct, key, value, arg7, flag, node_value,
    hashmap_slot) -> Status."""
    key_bytes = slots["key_build"](key, tag)
    prod1 = handle["product1"]
    if prod1["vtable_slot98"] == CANONICAL_PRODUCT1:
        found_obj = slots["product1_slot90"]()
    else:
        found_obj = slots["product1_slot98"]()
    if not slots["product1_slot10"](found_obj, key_bytes):
        return slots["insert"](out, handle, tag, direct, key_bytes,
                               value, arg7, 0, 0, 0)
    record = slots["product1_slot18"](found_obj)
    length, consumed = (varint_decode(record, 0) if record[0] & 0x80
                        else (record[0], 1))
    payload = record[consumed:consumed + length]
    prod2 = handle["product2"]
    if prod2["vtable_slot98"] == CANONICAL_PRODUCT2:
        ok = slots["product2_slot10"](prod2["sub20"], key_bytes)
    else:
        ok = slots["product2_slot98"](prod2, key_bytes)
    if not ok:
        return slots["insert"](out, handle, tag, direct, key_bytes,
                               value, arg7, 0, 0, 0)
    trailer = int.from_bytes(payload[length - 8:length], "little")
    if trailer & 0xFF != direct:
        return slots["insert"](out, handle, tag, direct, key_bytes,
                               value, arg7, 0, 0, 0)
    stored_len = slots["value_length"](record, consumed + length)
    new_len = len(value["data"])
    if new_len > stored_len:
        return slots["insert"](out, handle, tag, direct, key_bytes,
                               value, arg7, 0, 0, 0)
    # In-place update: re-encode the new value length at the
    # value position, then memcpy the new value over the old
    # one (the new value fits, so it fully covers the old).
    pos = consumed + length
    old_varint_len = len(varint_encode(stored_len))
    new_record = (record[:pos] + varint_encode(new_len) + value["data"]
                  + record[pos + old_varint_len + stored_len:])
    bucket = slots["bucket"](handle, key_bytes)
    slots["wrlock"](bucket)
    handle["record"] = new_record
    if handle.get("slot50") is not None:
        slots["notify"](handle["slot50"], 1, 0x27)
    value_end = pos + len(varint_encode(new_len)) + new_len
    if arg7 is None:
        slots["resolve"](handle, None, key_bytes, value, value_end,
                         trailer & 0xFF, trailer >> 8)
        out.code, out.code2, out.msg = 0, 0, None
    else:
        fold = [arg7[0]]
        hash_combine(fold, tag.to_bytes(8, "little"), 8,
                     (trailer >> 8).to_bytes(8, "little"), 8,
                     slots["hash64"], seed=SIBLING_FOLD_SEED)
        slots["resolve"](handle, fold[0], key_bytes, value, value_end,
                         trailer & 0xFF, trailer >> 8)
        slots["validate"](out, handle, record, trailer >> 8, value,
                          value_end)
    slots["unlock"](bucket)
    return out


def post_hook(owner, slots):
    """Post-write hook 0x5fb6a60..0x5fb6bbf (contract-level).
    slots: slot30() -> object; flush_once(obj) (0x5ed88c0);
    check_fn(obj) -> bool (0x5f13440); size_fn(obj, total) ->
    int (0x5f13430); slot78(obj) -> int; flush(obj, arg)
    (0x5f44db0)."""
    if owner.get("f18"):
        state = slots["slot30"]()
        if state.get("field_c68") == 1:
            # lock cmpxchg 1 -> 2: only the thread that wins
            # the swap runs the once-flush.
            state["field_c68"] = 2
            slots["flush_once"](owner["f18"])
    if owner.get("f20"):
        p = slots["slot30"]()
        limit = p.get("field_5f8", 0)
        if limit == 0:
            return
        if not slots["check_fn"](p.get("field_8f0")):
            return
        state = p.get("state_8e8", {})
        total = (slots["slot78"](state.get("f_a50"))
                 + slots["slot78"](state.get("f_a58"))
                 + state.get("f_a00", 0))
        total += slots["size_fn"](p.get("field_8f0"), total)
        if total < limit:
            return
        if p.get("field_8f1", 0) == 0:
            # lock cmpxchg 0 -> 1: only the thread that wins
            # the swap runs the threshold flush.
            p["field_8f1"] = 1
            slots["flush"](owner["f20"], p)


def _produce(owner, arg3, arg4, arg5, arg7, slots, handle):
    """The code-1 produce path at 0x5fc6468: build a
    rocksdb::SnapshotImpl (vtable 0x64c92d0, tag = the owner's
    +0x8, flag 1) and a 0x90-byte request, resolve the produce
    pointer through virtual slot 0x28 (or slot 0x3e8 when it
    is null), call virtual slot 0xe8, then dispatch on the
    handle's +0x40 function pointer. Returns the err Status
    that the shared tail then processes. When the produce
    object or the +0x30 field is missing, the default outcome
    is Status code 3."""
    if owner.get("f40") is None or owner.get("f30"):
        return Status(3, 0, None)
    snapshot = {"vtable": SNAPSHOT_VTABLE, "tag": owner.get("count8", 0),
                "flag": 1, "typeinfo": SNAPSHOT_TYPEINFO,
                "typeinfo_ptr": SNAPSHOT_TYPEINFO_PTR,
                "slots": SNAPSHOT_VTABLE_SLOTS}
    request = produce_request_init()
    request["snapshot"] = snapshot
    request["str_a"] = b""  # the -0xe0 string (first byte 0)
    request["str_b"] = b""  # the -0x100 string (first byte 0)
    key_slot = b""  # the -0x110 string (points at -0x100)
    p = slots["slot28"](owner["opts10"])
    if p is None:
        p = slots["slot3e8"](owner["f40"])
    produce = slots["slot_e8"](owner["f40"], request, p, arg4, key_slot)
    if produce.code > 1:
        result = Status(produce.code, produce.code2, None)
        if produce.msg is not None:
            slot = [None]
            strdup_into(slot, produce.msg)
            result.msg = slot[0]
        return result
    # Code <= 1: the err Status is cleared and the +0x40
    # function pointer is called. Code 0 passes the key-slot
    # string and its size; code 1 passes nulls.
    fn = slots["slot40_fn"]
    if produce.code == 0:
        string_arg, int_arg = key_slot, 0
    else:
        string_arg, int_arg = None, None
    ret = fn(string_arg, int_arg, arg5, request["str_a"])
    if ret == 0:
        return Status(0, 0, None)
    # Return 1 or 2: re-insert the record with the value struct
    # built from the string/int pair the return selects (1:
    # the key-slot string; 2: the request's str_a). The
    # hash-combine's first cell is *arg7 when arg7 is given;
    # with a null arg7 the combine is skipped and the insert's
    # stack arguments are all zero. The insert's type argument
    # is 1 in both cases.
    if ret == 1:
        pair = (key_slot, 0)
    else:
        pair = (request["str_a"], 0)
    if arg7 is not None:
        combined = [arg7[0]]
        hash_combine(combined, arg5["data"], arg5["len8"],
                     pair[0], pair[1], slots["hash64"])
        insert_arg7 = combined
    else:
        insert_arg7 = None
    value_struct = {"string": pair[0], "int": pair[1]}
    insert_status = Status()
    slots["record_insert"](insert_status, handle, owner.get("count8", 0),
                           1, arg4, value_struct, insert_arg7, 0, 0, 0)
    if insert_status.code == 0 and handle.get("slot50") is not None:
        slots["notify"](handle["slot50"], 1, 0x25)
    return insert_status


def record_write_caller(out, owner, arg3, arg4, arg5, direct, arg7, slots):
    """Record-write caller 0x5fc6070..0x5fc6e8b.
    owner: {"b1": closed flag, "a0": delegate object or None,
    "b0": flag byte, "count8": tag, "opts10": options object,
    "f18"/"f20": post-hook objects, "f28": flag, "f30": limit,
    "f38": register value, "f48": map present, "f49": map
    initialised, "f60": one-element list or None, "f101":
    hashmap skipped, "f102": hashmap initialised, "map70":
    RbMap, "hashmap110": HashMap, "f40": produce object}.
    arg4/arg5: {"data": bytes, "len8": int} slices. slots:
    the validate/fallback/hash64/slot20/sibling_write/
    record_write/record_insert/post_hook/check/produce/
    slot28/slot3e8/slot_e8/slot40_fn callables, plus an
    optional on_complete callback (the -0x88 slot, never
    written in the function: its construction site is not
    pinned, so it defaults to unset)."""
    result = _record_write_caller_inner(owner, arg3, arg4, arg5,
                                        direct, arg7, slots)
    status_move(out, result)
    if slots.get("on_complete") is not None:
        slots["on_complete"](3)
    return out


def _record_write_caller_inner(owner, arg3, arg4, arg5, direct, arg7, slots):
    # Closed path: delegate and return.
    if owner.get("b1") and owner.get("a0") is not None:
        st = Status()
        fallback(st, owner["a0"], arg3, arg4, arg5, slots["hash64"])
        return st
    # Validation.
    err = Status()
    if not validate(owner, err, slots):
        if err.code != 0:
            return err
        if owner.get("a0") is not None:
            fb = Status()
            fallback(fb, owner["a0"], arg3, arg4, arg5, slots["hash64"])
            if fb.code != 0:
                return fb
            if slots["check"](owner, arg3, arg4) == owner.get("b0", 0):
                owner["count8"] = owner.get("count8", 0) + 1
            return err
        if owner.get("b0", 0) == 0:
            owner["count8"] = owner.get("count8", 0) + 1
        return err
    handle = slots["slot20"]()
    if handle.get("flag31"):
        if handle.get("slot40") is None or direct != 1:
            st = Status()
            slots["sibling_write"](st, handle, owner.get("count8", 0),
                                   direct, arg4, arg5, arg7)
            return _common_tail_status(owner, arg3, arg4, arg5, slots, st)
        st = Status()
        slots["record_write"](st, handle, owner.get("count8", 0),
                              direct, arg4, arg5, arg7)
        if st.code == 1:
            st = _produce(owner, arg3, arg4, arg5, arg7, slots, handle)
        return _common_tail_status(owner, arg3, arg4, arg5, slots, st)
    # Fresh handle: hashmap find-or-insert, then the std::map
    # insert, then the record insert.
    if owner.get("f101"):
        hashmap_slot = None
    else:
        if not owner.get("f102"):
            owner["hashmap110"] = HashMap()
            owner["f102"] = True
        hashmap_slot = hashmap_find_or_insert(owner["hashmap110"],
                                              handle["id"])
    if owner.get("f48"):
        if not owner.get("f49"):
            owner["map70"] = RbMap()
            owner["f49"] = True
        node = map_insert(owner["map70"], handle["id"])
        node_value = node["value"]
    else:
        node_value = 0x28
    st = Status()
    slots["record_insert"](st, handle, owner.get("count8", 0), direct,
                           arg4, arg5, arg7, owner.get("f49", 0),
                           node_value, hashmap_slot)
    return _common_tail_status(owner, arg3, arg4, arg5, slots, st)


def _common_tail_status(owner, arg3, arg4, arg5, slots, st):
    """The shared tail as a Status (the move into the caller's
    out happens in record_write_caller)."""
    if st.code == 0x0D:
        if owner.get("b0", 0) != 0:
            owner["count8"] = owner.get("count8", 0) + 1
        return st
    if st.code == 0:
        if owner.get("b0", 0) == 0:
            owner["count8"] = owner.get("count8", 0) + 1
        post_hook(owner, slots)
        if owner.get("a0") is not None:
            fb = Status()
            fallback(fb, owner["a0"], arg3, arg4, arg5, slots["hash64"])
            return fb
        return st
    return st
