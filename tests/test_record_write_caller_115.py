"""Tests for tools/record_write_caller_115.py.

The virtual slots and the record operations pinned by the
#3337/#3330 packets are stubbed: the tests verify that the
caller passes the right key/tag/options/direct arguments and
takes the right branch, not the inner record semantics (those
are #3337's and #3330's ground). The 64-bit hash 0x61c3530 is
contract-only, so a deterministic stand-in is injected and
the tests check the fold structure and the seeds, not exact
hash outputs.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from record_write_caller_115 import (  # noqa: E402
    ABORTED_MEMORY_LIMIT, CANONICAL_PRODUCT1, CANONICAL_PRODUCT2,
    DIGEST, FALLBACK_HASH_SEEDS, HASH_SEED, HashMap, RbMap,
    SIBLING_FOLD_SEED, SNAPSHOT_VTABLE, Status, empty_status,
    fallback, hash_combine, hashmap_find_or_insert, map_insert,
    map_lower_bound, post_hook, produce_request_init,
    record_write_caller, register_min, sibling_write, status_build,
    status_move, strdup_into, validate, varint_decode, varint_encode,
)


def stub_hash64(data, length, seed):
    """Deterministic stand-in for the contract-only hash
    0x61c3530: distinguishes its inputs without claiming to
    be the real hash."""
    value = seed
    for i, byte in enumerate(bytes(data)[:length]):
        value = ((value * 1099511628211) ^ byte ^ i) & 0xFFFFFFFFFFFFFFFF
    return value ^ length


def make_owner(**overrides):
    owner = {
        "b1": 0, "a0": None, "b0": 0, "count8": 7, "opts10": {},
        "f18": None, "f20": None, "f28": 0, "f30": 0, "f38": 0,
        "f48": 0, "f49": 0, "f60": None, "f101": 0, "f102": 0,
        "map70": RbMap(), "hashmap110": HashMap(), "f40": None,
    }
    owner.update(overrides)
    return owner


def make_handle(**overrides):
    handle = {
        "id": 0x1000, "flag31": 1, "slot40": None, "slot50": None,
        "product1": {"vtable_slot98": CANONICAL_PRODUCT1},
        "product2": {"vtable_slot98": CANONICAL_PRODUCT2,
                     "sub20": object()},
    }
    handle.update(overrides)
    return handle


def make_fallback_obj(**overrides):
    obj = {"key": bytearray(64), "key_size": 0, "flags": 0,
           "klen28": 0, "hashes": [], "hash_slack": 0}
    obj.update(overrides)
    return obj


def base_slots(**overrides):
    """A slots dict whose callables record their calls and
    return the neutral outcome, so each test only overrides
    what its scenario needs."""
    calls = []

    def record(name):
        def fn(*args, **kwargs):
            calls.append((name, args))
            return None
        return fn

    slots = {
        "hash64": stub_hash64,
        "slot10": lambda: True,
        "slot18": lambda: 0,
        "slot20": lambda: None,
        "register": register_min,
        "check": lambda owner, a3, a4: 0,
        "sibling_write": lambda out, h, t, d, k, v, a7: setattr(
            out, "code", 0) or out,
        "record_write": lambda out, h, t, d, k, v, a7: setattr(
            out, "code", 0) or out,
        "record_insert": lambda out, h, t, d, k, v, a7, f, n, s: setattr(
            out, "code", 0) or out,
        "slot28": lambda opts: object(),
        "slot3e8": lambda f40: object(),
        "slot_e8": lambda f40, req, p, a4, ks: Status(0, 0, None),
        "slot40_fn": lambda s, i, a5, sa: 0,
        "post_hook": lambda owner: None,
        "on_complete": None,
        "calls": calls,
    }
    slots.update(overrides)
    return slots


# --- primitives -------------------------------------------------------

def test_varint_round_trip():
    for value in (0, 1, 127, 128, 300, 16383, 16384, 0xFFFFFFFF):
        encoded = varint_encode(value)
        decoded, pos = varint_decode(encoded, 0)
        assert decoded == value and pos == len(encoded), value
    # The short form is a single byte; the payload follows it.
    assert varint_decode(bytes([5, 9, 9]), 0) == (5, 1)
    assert varint_encode(0) == b"\x00"
    assert varint_encode(300) == b"\xac\x02"


def test_status_move_and_build():
    src = Status(4, 0, "Invalid column family specified in write batch")
    dst = Status(0, 0, None)
    status_move(dst, src)
    assert dst == Status(4, 0, "Invalid column family specified in write batch")
    assert src == Status(0, 0, None)
    assert status_build(4, "key is too large") == Status(4, 0, "key is too large")
    assert empty_status() == Status(0, 0, None)


def test_produce_request_fields():
    req = produce_request_init()
    assert req[0x2C] == 0x001  # 0x101 as initialised, 0x2d byte cleared
    assert req[0x78] == -1 and req[0x84] == 4 and req[0x88] == 0x100
    assert req[0x00] == 0 and req[0x20] == 0


def test_strdup_into():
    slot = [None]
    strdup_into(slot, b"hello")
    assert slot[0] == b"hello"


def test_hashmap_find_or_insert_and_rehash():
    table = HashMap()
    cell_a = hashmap_find_or_insert(table, 0x1000)
    assert cell_a == [0] and table.size == 1
    cell_a[0] = 42
    assert hashmap_find_or_insert(table, 0x1000) == [42]
    # A second key forces a rehash (load would exceed 1.0).
    hashmap_find_or_insert(table, 0x2000)
    assert table.count > 1
    assert hashmap_find_or_insert(table, 0x1000) == [42]
    assert hashmap_find_or_insert(table, 0x2000) == [0]


def test_map_lower_bound_and_insert():
    tree = RbMap()
    node, hint = map_lower_bound(tree, 5)
    assert node is None and hint is None
    first = map_insert(tree, 5)
    assert map_insert(tree, 5) is first  # present: no new node
    node, hint = map_lower_bound(tree, 5)
    assert node is first and hint == 5
    node, hint = map_lower_bound(tree, 3)
    assert node is None and hint == 5  # the insert would attach at 5
    node, hint = map_lower_bound(tree, 9)
    assert node is None and hint is None


def test_register_min():
    handle = {}
    register_min(handle, 10)
    assert handle["reg_c38"] == 10
    register_min(handle, 20)
    assert handle["reg_c38"] == 10  # min wins
    register_min(handle, 5)
    assert handle["reg_c38"] == 5


# --- validator ---------------------------------------------------------

def test_validate_open_and_limit():
    owner = make_owner(f30=5)
    out = Status()
    slots = {"slot10": lambda: True, "slot18": lambda: 10,
             "slot20": lambda: None, "register": register_min}
    assert validate(owner, out, slots) is False
    assert out == Status(0, 0, None)  # f30 < limit: empty, false
    owner["f30"] = 10
    assert validate(owner, out, slots) is True  # f30 == limit: passes


def test_validate_closed_and_register():
    owner = make_owner(f28=0, f38=7)
    out = Status()
    seen = []
    slots = {"slot10": lambda: False,
             "slot18": lambda: 0, "slot20": lambda: {"id": 1},
             "register": lambda h, v: seen.append((h, v))}
    assert validate(owner, out, slots) is False
    assert out.code == 4 and "Invalid column family" in out.msg
    owner["f28"] = 1
    assert validate(owner, out, slots) is False
    assert out == Status(0, 0, None)  # f28 set: empty status
    flag = [0]
    owner = make_owner(f38=7, f60=flag)
    slots["slot10"] = lambda: True
    assert validate(owner, out, slots) is True
    assert flag == [1]  # the +0x60 byte is set
    assert seen == [({"id": 1}, 7)]  # the min-register runs


# --- fallback ----------------------------------------------------------

def test_fallback_gates():
    out = Status()
    obj = make_fallback_obj()
    arg4 = {"data": b"K", "len8": 0x100000000}
    arg5 = {"data": b"V", "len8": 1}
    fallback(out, obj, 3, arg4, arg5, stub_hash64)
    assert out == Status(4, 0, "key is too large")
    arg4["len8"] = 1
    arg5["len8"] = 0x100000000
    fallback(out, obj, 3, arg4, arg5, stub_hash64)
    assert out == Status(4, 0, "value is too large")


def test_fallback_append_and_hash():
    out = Status()
    obj = make_fallback_obj()
    arg4 = {"data": b"K", "len8": 1}
    arg5 = {"data": b"V", "len8": 1}
    fallback(out, obj, 3, arg4, arg5, stub_hash64)
    assert out == Status(0, 0, None)
    assert obj["flags"] == 2
    # The setter bumps the size by 1 first, so the byte at the
    # old size index is the stale buffer byte (0 here), then
    # the leading 5, varint(3), varint(1), "K", varint(1), "V".
    assert bytes(obj["key"][:obj["key_size"]]) == (
        b"\x00\x05\x03\x01K\x01V")
    assert len(obj["hashes"]) == 1
    expected = stub_hash64(b"K", 1, FALLBACK_HASH_SEEDS[0])
    expected ^= stub_hash64(b"V", 1, FALLBACK_HASH_SEEDS[1])
    expected ^= stub_hash64(b"\x01", 1, FALLBACK_HASH_SEEDS[2])
    expected ^= stub_hash64((3).to_bytes(4, "little"), 4,
                            FALLBACK_HASH_SEEDS[3])
    assert obj["hashes"][0] == expected


def test_fallback_arg3_zero_and_rollback():
    out = Status()
    obj = make_fallback_obj()
    fallback(out, obj, 0, {"data": b"K", "len8": 1},
             {"data": b"V", "len8": 1}, stub_hash64)
    assert bytes(obj["key"][:obj["key_size"]]) == b"\x00\x01\x01K\x01V"
    # A maximum length of 2: the built key exceeds it, so the
    # append rolls back and reports Aborted(MemoryLimit).
    obj = make_fallback_obj(klen28=2)
    fallback(out, obj, 3, {"data": b"K", "len8": 1},
             {"data": b"V", "len8": 1}, stub_hash64)
    assert out.code == ABORTED_MEMORY_LIMIT and out.code2 == 0
    assert out.msg is None
    assert obj["key_size"] == 0 and obj["hashes"] == []
    assert obj["flags"] == 0
    # A zero maximum disables the check; a large one keeps it.
    obj = make_fallback_obj(klen28=0)
    fallback(out, obj, 3, {"data": b"K", "len8": 1},
             {"data": b"V", "len8": 1}, stub_hash64)
    assert out == Status(0, 0, None) and obj["key_size"] == 7


# --- sibling write ------------------------------------------------------

def _sibling_slots(**overrides):
    # varint(11) + payload ("PAY" + 8-byte trailer 0x2a) +
    # varint(1) + value "V": the trailer's low byte is the
    # direct byte, the stored value length is 1.
    record = bytes([11]) + b"PAY" + (0x2A).to_bytes(8, "little")
    record += varint_encode(1) + b"V"
    slots = {
        "key_build": lambda k, t: b"KEY",
        "product1_slot90": lambda: object(),
        "product1_slot98": lambda: object(),
        "product1_slot10": lambda o, k: True,
        "product1_slot18": lambda o: record,
        "product2_slot10": lambda o, k: True,
        "product2_slot98": lambda o, k: True,
        "value_length": lambda rec, pos: varint_decode(rec, pos)[0],
        "bucket": lambda h, k: 3,
        "wrlock": lambda b: None,
        "unlock": lambda b: None,
        "notify": lambda o, a, b: None,
        "hash64": stub_hash64,
        "resolve": lambda *a: None,
        "validate": lambda *a: None,
        "insert": lambda *a: Status(0, 0, None),
        "record": record,
    }
    slots.update(overrides)
    return slots


def test_sibling_update_path():
    handle = make_handle(slot50=object())
    out = Status()
    seen = {}
    slots = _sibling_slots(
        resolve=lambda h, f, k, v, ve, t, hi: seen.setdefault("fold", f),
        validate=lambda *a: seen.setdefault("validated", True),
        notify=lambda o, a, b: seen.setdefault("notified", (a, b)))
    tag = 7
    sibling_write(out, handle, tag, 0x2A, {"data": b"K", "len8": 1},
                  {"data": b"W", "len8": 1}, [0x1234], slots)
    assert out == Status(0, 0, None)
    assert seen["notified"] == (1, 0x27)
    assert seen["validated"] is True
    expected = 0x1234
    expected ^= stub_hash64(tag.to_bytes(8, "little"), 8, SIBLING_FOLD_SEED)
    expected ^= stub_hash64((0).to_bytes(8, "little"), 8, SIBLING_FOLD_SEED)
    assert seen["fold"] == expected  # trailer>>8 is 0 here
    assert handle["record"][13:14] == b"W"  # the value overwritten


def test_sibling_insert_paths():
    handle = make_handle()
    out = Status()
    inserted = []
    slots = _sibling_slots(
        insert=lambda *a: inserted.append(a) or Status(0, 0, None))
    # Product-1 has no record for the key.
    slots["product1_slot10"] = lambda o, k: False
    sibling_write(out, handle, 7, 0x2A, {"data": b"K", "len8": 1},
                  {"data": b"V", "len8": 1}, None, slots)
    assert len(inserted) == 1 and inserted[0][6] is None
    # Trailer low byte differs from direct.
    slots["product1_slot10"] = lambda o, k: True
    sibling_write(out, handle, 7, 0x2B, {"data": b"K", "len8": 1},
                  {"data": b"V", "len8": 1}, None, slots)
    assert len(inserted) == 2
    # New value longer than the stored value.
    sibling_write(out, handle, 7, 0x2A, {"data": b"K", "len8": 1},
                  {"data": b"VW", "len8": 2}, None, slots)
    assert len(inserted) == 3


def test_sibling_arg7_none_skips_fold():
    handle = make_handle()
    out = Status()
    seen = {}
    slots = _sibling_slots(
        resolve=lambda h, f, *a: seen.setdefault("fold", f),
        validate=lambda *a: seen.setdefault("validated", True))
    sibling_write(out, handle, 7, 0x2A, {"data": b"K", "len8": 1},
                  {"data": b"V", "len8": 1}, None, slots)
    assert seen["fold"] is None and "validated" not in seen
    assert out == Status(0, 0, None)


# --- post-write hook ----------------------------------------------------

def test_post_hook_once_and_threshold():
    state = {"field_c68": 1}
    p = {"field_5f8": 10, "field_8f0": object(), "field_8f1": 0,
         "state_8e8": {"f_a50": 1, "f_a58": 2, "f_a00": 3}}
    owner = make_owner(f18=object(), f20=object())
    flushed = []
    slots = {
        "slot30": lambda: state if flushed == [] else p,
        "flush_once": lambda o: flushed.append("once"),
        "check_fn": lambda o: True,
        "size_fn": lambda o, t: 4,
        "slot78": lambda o: 0,
        "flush": lambda o, a: flushed.append("threshold"),
    }
    # The first call: the once-flush runs (CAS 1 -> 2) and the
    # threshold flush runs (0 + 0 + 3 + 4 = 7 < 10? no: 7 < 10,
    # so no threshold flush yet).
    post_hook(owner, slots)
    assert flushed == ["once"] and state["field_c68"] == 2
    # Raise the sizes so the total reaches the limit.
    slots["slot78"] = lambda o: 5
    post_hook(owner, slots)
    assert flushed == ["once", "threshold"] and p["field_8f1"] == 1
    # A third call flushes nothing: both CAS flags are spent.
    post_hook(owner, slots)
    assert flushed == ["once", "threshold"]


def test_post_hook_limits():
    owner = make_owner(f20=object())
    p = {"field_5f8": 0, "field_8f0": object(), "field_8f1": 0,
         "state_8e8": {}}
    flushed = []
    slots = {"slot30": lambda: p, "flush_once": lambda o: None,
             "check_fn": lambda o: True, "size_fn": lambda o, t: 0,
             "slot78": lambda o: 0,
             "flush": lambda o, a: flushed.append("x")}
    post_hook(owner, slots)
    assert flushed == []  # limit 0: no flush
    p["field_5f8"] = 5
    slots["check_fn"] = lambda o: False
    post_hook(owner, slots)
    assert flushed == []  # the check fails: no flush


# --- dispatcher ---------------------------------------------------------

def _call(owner, slots, arg3=3, direct=1, arg7=None):
    out = Status()
    arg4 = {"data": b"K", "len8": 1}
    arg5 = {"data": b"V", "len8": 1}
    record_write_caller(out, owner, arg3, arg4, arg5, direct, arg7, slots)
    return out


def test_dispatcher_closed_path():
    owner = make_owner(b1=1, a0=make_fallback_obj())
    out = _call(owner, base_slots())
    assert out == Status(0, 0, None)
    # The delegate ran: the key string grew by the fallback.
    assert owner["a0"]["key_size"] == 7


def test_dispatcher_closed_without_delegate_falls_to_validate():
    owner = make_owner(b1=1, a0=None)
    slots = base_slots(slot20=lambda: make_handle())
    out = _call(owner, slots)
    assert out == Status(0, 0, None)  # validate passes, sibling runs


def test_dispatcher_validate_failure_returns_validator_status():
    owner = make_owner()
    slots = base_slots(slot10=lambda: False)
    out = _call(owner, slots)
    assert out.code == 4 and "Invalid column family" in out.msg


def test_dispatcher_validate_failure_with_delegate():
    owner = make_owner(a0=make_fallback_obj())
    slots = base_slots(slot10=lambda: False)
    owner["f28"] = 1  # the validator fails with an empty status
    out = _call(owner, slots)
    # The delegate ran with code 0, the check (0) equals b0 (0),
    # so the tag is bumped and the empty status is returned.
    assert out == Status(0, 0, None) and owner["count8"] == 8
    # A failing delegate status is returned as-is.
    slots = base_slots(slot10=lambda: False)
    owner = make_owner(a0=make_fallback_obj())
    owner["f28"] = 1
    owner["a0"]["klen28"] = 1  # the fallback will roll back: 0x70a
    out = _call(owner, slots)
    assert out.code == ABORTED_MEMORY_LIMIT


def test_dispatcher_validate_failure_no_delegate_bumps_when_b0_clear():
    owner = make_owner(a0=None, b0=0)
    slots = base_slots(slot10=lambda: False)
    owner["f28"] = 1
    out = _call(owner, slots)
    assert out == Status(0, 0, None) and owner["count8"] == 8
    owner["b0"] = 1
    out = _call(owner, slots)
    assert owner["count8"] == 8  # b0 set: no bump


def test_dispatcher_sibling_path_and_tail():
    owner = make_owner()
    seen = {}
    handle = make_handle(slot40=None)
    slots = base_slots(
        slot20=lambda: handle,
        sibling_write=lambda out, h, t, d, k, v, a7: (
            seen.setdefault("sibling", (t, d, k, v, a7)),
            setattr(out, "code", 0))[1])
    out = _call(owner, slots)
    assert out == Status(0, 0, None)
    assert seen["sibling"][0] == 7  # tag = owner+0x8
    assert seen["sibling"][1] == 1  # direct
    assert owner["count8"] == 8  # code 0 + b0 clear: bump


def test_dispatcher_sibling_tryagain_bumps_only_when_b0_set():
    owner = make_owner(b0=1)
    handle = make_handle(slot40=None)
    slots = base_slots(
        slot20=lambda: handle,
        sibling_write=lambda out, h, t, d, k, v, a7: setattr(
            out, "code", 0x0D) or out)
    out = _call(owner, slots)
    assert out.code == 0x0D and owner["count8"] == 8
    owner["b0"] = 0
    out = _call(owner, slots)
    assert owner["count8"] == 8  # code 0x0d + b0 clear: no bump


def test_dispatcher_record_write_and_produce():
    owner = make_owner(f40=object())
    handle = make_handle(slot40=object())
    seen = {}
    slots = base_slots(
        slot20=lambda: handle,
        record_write=lambda out, h, t, d, k, v, a7: setattr(
            out, "code", 1) or out,
        slot28=lambda opts: "produce-pointer",
        slot_e8=lambda f40, req, p, a4, ks: (
            seen.setdefault("produce", (req, p, ks)),
            Status(0, 0, None))[1],
        slot40_fn=lambda s, i, a5, sa: (
            seen.setdefault("fn", (s, i, a5, sa)), 0)[1])
    out = _call(owner, slots)
    assert out == Status(0, 0, None)
    assert seen["produce"][1] == "produce-pointer"
    assert seen["produce"][0]["snapshot"]["vtable"] == SNAPSHOT_VTABLE
    assert seen["produce"][0]["snapshot"]["tag"] == 7
    # Code 0 passes the key-slot string and its size (0).
    assert seen["fn"][0] == b"" and seen["fn"][1] == 0
    assert owner["count8"] == 8  # the shared tail bumped the tag


def test_dispatcher_produce_code_1_passes_nulls():
    owner = make_owner(f40=object())
    handle = make_handle(slot40=object())
    seen = {}
    slots = base_slots(
        slot20=lambda: handle,
        record_write=lambda out, h, t, d, k, v, a7: setattr(
            out, "code", 1) or out,
        slot_e8=lambda f40, req, p, a4, ks: Status(1, 0, None),
        slot40_fn=lambda s, i, a5, sa: (
            seen.setdefault("fn", (s, i)), 0)[1])
    out = _call(owner, slots)
    assert out == Status(0, 0, None)
    assert seen["fn"] == (None, None)  # code 1: null string/int


def test_dispatcher_produce_code_above_1_copies_with_strdup():
    owner = make_owner(f40=object())
    handle = make_handle(slot40=object())
    slots = base_slots(
        slot20=lambda: handle,
        record_write=lambda out, h, t, d, k, v, a7: setattr(
            out, "code", 1) or out,
        slot_e8=lambda f40, req, p, a4, ks: Status(5, 0, b"boom"))
    out = _call(owner, slots)
    assert out == Status(5, 0, b"boom")  # the message is duplicated


def test_dispatcher_produce_default_code_3():
    owner = make_owner(f40=None)  # no produce object
    handle = make_handle(slot40=object())
    slots = base_slots(
        slot20=lambda: handle,
        record_write=lambda out, h, t, d, k, v, a7: setattr(
            out, "code", 1) or out)
    out = _call(owner, slots)
    assert out == Status(3, 0, None)


def test_dispatcher_produce_reinsert_type_2():
    owner = make_owner(f40=object())
    handle = make_handle(slot40=object(), slot50=object())
    seen = {}
    slots = base_slots(
        slot20=lambda: handle,
        record_write=lambda out, h, t, d, k, v, a7: setattr(
            out, "code", 1) or out,
        slot_e8=lambda f40, req, p, a4, ks: Status(0, 0, None),
        slot40_fn=lambda s, i, a5, sa: 2,
        record_insert=lambda out, h, t, d, k, v, a7, f, n, s: (
            seen.setdefault("insert", (t, d, k, v, a7)),
            setattr(out, "code", 0))[1],
        notify=lambda o, a, b: seen.setdefault("notified", (a, b)))
    out = _call(owner, slots, arg7=[0x7777])
    assert out == Status(0, 0, None)
    assert seen["insert"][0] == 7 and seen["insert"][1] == 1
    assert seen["insert"][3]["string"] == b""  # type 2: str_a
    assert seen["insert"][4][0] != 0  # the combined cell is passed
    assert seen["notified"] == (1, 0x25)  # the +0x50 notify


def test_dispatcher_fresh_handle_hashmap_and_map():
    owner = make_owner(f101=0, f102=0, f48=1, f49=0)
    handle = make_handle(flag31=0)
    seen = {}
    slots = base_slots(
        slot20=lambda: handle,
        record_insert=lambda out, h, t, d, k, v, a7, f, n, s: (
            seen.setdefault("insert", (f, n, s)),
            setattr(out, "code", 0))[1])
    out = _call(owner, slots)
    assert out == Status(0, 0, None)
    assert owner["f102"] == 1 and owner["f49"] == 1
    assert seen["insert"][2] is not None  # the hashmap value cell
    assert seen["insert"][1] == 0  # the new map node's value
    # A second call reuses the same hashmap cell and map node.
    out = _call(owner, slots)
    assert seen["insert"][2] is not None
    assert len(owner["map70"].entries) == 1


def test_dispatcher_fresh_handle_skips_hashmap_and_map():
    owner = make_owner(f101=1, f48=0)
    handle = make_handle(flag31=0)
    seen = {}
    slots = base_slots(
        slot20=lambda: handle,
        record_insert=lambda out, h, t, d, k, v, a7, f, n, s: (
            seen.setdefault("insert", (f, n, s)),
            setattr(out, "code", 0x0D))[1])
    owner["b0"] = 1
    out = _call(owner, slots)
    assert out.code == 0x0D and owner["count8"] == 8
    assert seen["insert"] == (0, 0x28, None)  # no map node: 0x28


def test_dispatcher_on_complete_and_digest():
    owner = make_owner()
    seen = []
    slots = base_slots(slot20=lambda: make_handle(),
                       on_complete=lambda arg: seen.append(arg))
    out = _call(owner, slots)
    assert out == Status(0, 0, None) and seen == [3]
    assert DIGEST.startswith("a6e2897c")


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_")]
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - report and continue
            failed += 1
            print("FAIL %s: %r" % (name, exc))
    print("%d tests, %d failed" % (len(tests), failed))
    raise SystemExit(1 if failed else 0)
