"""Tests for tools/record_insert_115.py (run directly; no pytest
on this VM).

Usage (from the repository root):
    python3 tests/test_record_insert_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import record_insert_115 as model

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("check failed: %s" % label)


def zero_hash(data, length, seed):
    return 0


def canonical_product():
    """A product whose vtable slot 0 is the forwarder and
    whose dispatch slots are all canonical."""
    return {
        "slot0": None,
        "inner_slot2": lambda size: bytearray(size),
        "slots": {0x08: lambda keybuf, *a: None,
                  0x10: "canonical", 0x18: "canonical",
                  0x20: "canonical", 0x28: "canonical",
                  0x30: "canonical", 0x38: "canonical",
                  0x40: "canonical"},
    }


def insert_args(**over):
    args = {
        "part1": (b"key", 3), "part2": (b"val", 3),
        "keypart": 42, "typ": 3, "direct": 0x1234,
        "protection": None, "flag": 0, "context": None,
        "counters": {"total": 0, "count": 0, "typed": 0},
        "hash64": zero_hash,
    }
    args.update(over)
    return args


def main():
    # Varint encode boundaries (0x61bd410).
    check(model.encode_varint32(0) == b"\x00", "varint 0")
    check(model.encode_varint32(0x7F) == b"\x7f", "varint 0x7f")
    check(model.encode_varint32(0x80) == b"\x80\x01", "varint 0x80")
    check(model.encode_varint32(0x3FFF) == b"\xff\x7f",
          "varint 0x3fff")
    check(model.encode_varint32(0x1FFFFF) == b"\xff\xff\x7f",
          "varint 0x1fffff")
    check(model.encode_varint32(0xFFFFFFF) == b"\xff\xff\xff\x7f",
          "varint 0xfffffff")
    for value in (0, 1, 0x7F, 0x80, 0x3FFF, 0x1FFFFF,
                  0xFFFFFFF, 0xFFFFFFFF):
        check(model.varint_len(value) ==
              len(model.encode_varint32(value)),
              "varint_len matches encode for %#x" % value)
    check(model.decode_varint32(b"\x80\x01", 0) == (0x80, 2),
          "varint decode 0x80")
    check(model.decode_varint32(b"\x0b", 0) == (11, 1),
          "varint decode 11")
    check(model.decode_varint32(b"\x80", 0) is None,
          "varint decode truncated")

    # Hash32 (0x61c34a0): empty input returns the seed.
    check(model.hash32(b"", 0) == 0, "hash32 empty seed 0")
    check(model.hash32(b"", 5) == 5, "hash32 empty seed 5")
    check(model.hash32(b"a", 0) == 0xCA6C9DD6, "hash32 'a'")
    check(model.hash32(b"abcd", 0) == 0x9E87A0D0,
          "hash32 'abcd' (one word)")
    check(model.hash32(b"abcde", 0xBC9F1D34) == 0x41D2C26D,
          "hash32 'abcde' seed 0xbc9f1d34")
    check(model.hash32(b"hello", 0xBC9F1D34) == 0xF795964E,
          "hash32 'hello' seed 0xbc9f1d34")
    check(model.hash32(b"a", 0) != model.hash32(b"b", 0),
          "hash32 differs across bytes")
    check(model.hash32(b"a", 0) != model.hash32(b"a", 1),
          "hash32 differs across seeds")

    # Key build layout and total formula.
    part1, part2 = b"ABC", b"DE"
    total = model.key_total(part1, part2, 4)
    check(total == 1 + 3 + 8 + 1 + 2 + 4, "key total 19")
    key = model.build_key(part1, part2, 0x1234, 7, 4)
    check(len(key) == 19, "key length is the total")
    check(key[0] == 0x0B, "key first varint is L1+8")
    check(key[1:4] == b"ABC", "key part1 bytes")
    check(int.from_bytes(key[4:12], "little") ==
          (0x1234 << 8) | 7, "key trailer is (keypart<<8)|type")
    check(key[12] == 0x02, "key second varint is L2")
    check(key[13:15] == b"DE", "key part2 bytes")
    check(key[15:19] == b"\x00\x00\x00\x00", "key tail zeros")
    check(model.key_total(b"", b"", 0) == 1 + 0 + 8 + 1 + 0 + 0,
          "key total empty parts")

    # Resolve (0x5f09e90): direct value, width arms.
    check(model.resolve_value(0xDEADBEEF, (b"a", 1), (b"b", 1),
                              1, 7, 4, zero_hash) ==
          b"\xef\xbe\xad\xde", "resolve direct width 4")
    check(model.resolve_value(0x123, (b"a", 1), (b"b", 1),
                              1, 7, 1, zero_hash) == b"\x23",
          "resolve direct width 1")
    check(model.resolve_value(0x12345, (b"a", 1), (b"b", 1),
                              1, 7, 2, zero_hash) == b"\x45\x23",
          "resolve direct width 2")
    check(model.resolve_value(0x1122334455667788, (b"a", 1),
                              (b"b", 1), 1, 7, 8, zero_hash) ==
          bytes.fromhex("8877665544332211"),
          "resolve direct width 8")
    check(model.resolve_value(0x1234, (b"a", 1), (b"b", 1),
                              1, 7, 0, zero_hash) == b"",
          "resolve width 0 stores nothing")

    # Resolve fold: the four-way xor with the pinned seeds.
    calls = []

    def spy_hash(data, length, seed):
        calls.append((bytes(data), length, seed))
        return seed ^ length

    stored = model.resolve_value(
        None, (b"ab", 2), (b"c", 1), 2, 9, 8, spy_hash)
    expected = (model.HASH64_SEEDS[0] ^ 2) ^ \
        (model.HASH64_SEEDS[1] ^ 1) ^ \
        (model.HASH64_SEEDS[2] ^ 1) ^ \
        (model.HASH64_SEEDS[3] ^ 8)
    check(stored == expected.to_bytes(8, "little"),
          "resolve fold is the four-way xor")
    check(calls[0][2] == model.HASH64_SEEDS[0],
          "fold seed 0 for slice_a")
    check(calls[1][2] == model.HASH64_SEEDS[1],
          "fold seed 1 for slice_b")
    check(calls[2][2] == model.HASH64_SEEDS[2],
          "fold seed 2 for the byte input")
    check(calls[3][2] == model.HASH64_SEEDS[3],
          "fold seed 3 for the qword input")
    check(calls[2][0] == b"\x02", "fold byte input is L1 & 0xff")
    check(calls[3][0] == (9).to_bytes(8, "little"),
          "fold qword input is the keypart")

    # Validate (0x5f09b10): a well-formed record passes with
    # the zero hash and protection 0; protection 1 fails.
    def record(key_payload, value_payload):
        key_len = len(key_payload) + 8
        trailer = (0x1234 << 8 | 7).to_bytes(8, "little")
        return (model.encode_varint32(key_len) + key_payload
                + trailer
                + model.encode_varint32(len(value_payload))
                + value_payload)

    good = record(b"key", b"val")
    check(model.validate_key(good, 0, 0, zero_hash) == (True, None),
          "validate accepts a well-formed record")
    check(model.validate_key(good, 0, 1, zero_hash)[0] is False,
          "validate rejects a protection mismatch")
    check(model.validate_key(good, 0, 1, zero_hash)[1] ==
          b"ProtectionInfo mismatch",
          "validate mismatch message")
    check(model.validate_key(b"\x80", 0, 0, zero_hash)[1] ==
          b"Unable to parse internal key length",
          "validate truncated key varint")
    check(model.validate_key(model.encode_varint32(3) + b"ab"
                             + b"\x00" * 8, 0, 0, zero_hash)[1] ==
          b"Internal key length too short",
          "validate key too short")
    check(model.validate_key(model.encode_varint32(100) + b"ab",
                             0, 0, zero_hash)[1] ==
          b"Internal key length too long",
          "validate key too long")
    check(model.validate_key(record(b"key", b"")[:-1], 0, 0,
                             zero_hash)[1] ==
          b"Unable to parse value length",
          "validate truncated value varint")
    buf = model.encode_varint32(11) + b"key" + \
        (0x1234 << 8 | 7).to_bytes(8, "little") + \
        model.encode_varint32(1) + b"vX"
    check(model.validate_key(buf, 0, 0, zero_hash)[1] ==
          b"Value length too short",
          "validate value too short")
    buf = model.encode_varint32(11) + b"key" + \
        (0x1234 << 8 | 7).to_bytes(8, "little") + \
        model.encode_varint32(9) + b"val"
    check(model.validate_key(buf, 0, 0, zero_hash)[1] ==
          b"Value length too long",
          "validate value too long")

    # Bloom insert (0x5f0eb8c): bits land in the right words
    # and a second insert changes nothing.
    words = {}
    model.bloom_insert(words, 0x1000, 3, b"hello")
    check(len(words) > 0, "bloom sets words")
    snapshot = dict(words)
    model.bloom_insert(words, 0x1000, 3, b"hello")
    check(words == snapshot, "bloom insert is idempotent")
    h = model.hash32(b"hello", model.HASH32_SEED)
    state = (h * model.GOLDEN64) & model.MASK64
    mix_hi = ((0x1000 * h) & model.MASK64) >> 32
    for i in range(3):
        index = (mix_hi ^ i) & model.MASK64
        bits = ((1 << (state & 63))
                | (1 << ((state >> 6) & 63)))
        check(words.get(index, 0) & bits == bits,
              "bloom probe %d sets its two bits" % i)
        state = ((state >> 12) | ((state & 0xFFF) << 52)) \
            & model.MASK64
    words0 = {}
    model.bloom_insert(words0, 0x1000, 0, b"hello")
    check(words0 == {}, "bloom zero probes sets nothing")

    # Min-install (0x5f0ec22 / 0x5f0f188). Block A installs
    # rbx when (old-1) >= rbx; block B, gated on C20 being
    # the sentinel or rbx < C20, installs rbx when C18 ==
    # C20, C18 is the sentinel, or rbx < C18. The
    # first-install path runs only when C18 is still 0
    # afterwards, which is exactly when rbx is 0.
    check(model.min_install(0, model.C20_SENTINEL, 5) ==
          (5, model.C20_SENTINEL),
          "min-install first install sets c18, c20 stays sentinel")
    check(model.min_install(0, 10, 5) == (5, 10),
          "min-install first install keeps c20")
    check(model.min_install(10, model.C20_SENTINEL, 5) ==
          (5, model.C20_SENTINEL),
          "min-install lowers the minimum")
    check(model.min_install(5, model.C20_SENTINEL, 10) ==
          (5, model.C20_SENTINEL),
          "min-install keeps a smaller minimum")
    check(model.min_install(1, model.C20_SENTINEL, 0) == (0, 0),
          "min-install zero installs and copies to c20")
    check(model.min_install(0, 0, 7) == (7, 0),
          "min-install with c20 zero keeps c20")
    check(model.min_install(0, model.C20_SENTINEL, 0) == (0, 0),
          "min-install zero from fresh sets both to zero")
    check(model.min_install(model.C20_SENTINEL,
                            model.C20_SENTINEL,
                            0x00FFFFFFFFFFFFFF + 1) ==
          (0x00FFFFFFFFFFFFFF + 1, model.C20_SENTINEL),
          "min-install a value above the sentinel replaces it")
    c18, c20 = 0, model.C20_SENTINEL
    for rbx, want in ((10, 10), (7, 7), (9, 7), (3, 3)):
        c18, c20 = model.min_install(c18, c20, rbx)
        check(c18 == want, "min-install decreasing to %d" % want)
    check(c20 == model.C20_SENTINEL,
          "min-install c20 stays sentinel for nonzero keys")

    # Product dispatch: canonical vs non-canonical slots.
    product = canonical_product()
    check(model.dispatch_commit(product, object(), b"k") ==
          ("ok", 0x38), "commit canonical context arm -> slot 0x38")
    check(model.dispatch_commit(product, None, b"k") ==
          ("ok", 0x38), "commit canonical null context -> slot 0x38")
    product["slots"][0x30] = lambda k, c: True
    check(model.dispatch_commit(product, object(), b"k") ==
          ("ok", 0x30), "commit non-canonical slot 0x30 true")
    product["slots"][0x30] = lambda k, c: False
    check(model.dispatch_commit(product, object(), b"k") ==
          ("try_again", 0x30), "commit slot 0x30 false -> try again")
    product["slots"][0x30] = "canonical"
    product["slots"][0x28] = lambda k, c: None
    check(model.dispatch_commit(product, object(), b"k") ==
          ("ok", 0x28), "commit non-canonical slot 0x28")
    product["slots"][0x28] = "canonical"
    product["slots"][0x40] = lambda k: False
    check(model.dispatch_commit(product, None, b"k") ==
          ("try_again", 0x40), "commit slot 0x40 false -> try again")
    product["slots"][0x40] = lambda k: True
    check(model.dispatch_commit(product, None, b"k") ==
          ("ok", 0x40), "commit slot 0x40 true")
    product["slots"][0x40] = "canonical"
    product["slots"][0x20] = lambda k, v: True
    check(model.dispatch_map(product, b"k", [None]) ==
          ("ok", 0x20), "map slot 0x20 true")
    product["slots"][0x20] = lambda k, v: False
    check(model.dispatch_map(product, b"k", [None]) ==
          ("try_again", 0x20), "map slot 0x20 false -> try again")
    product["slots"][0x20] = "canonical"
    product["slots"][0x18] = lambda k, v: None
    check(model.dispatch_map(product, b"k", [None]) ==
          ("ok", 0x18), "map slot 0x18")
    product["slots"][0x18] = "canonical"
    check(model.dispatch_map(product, b"k", [None]) ==
          ("ok", 0x08), "map all canonical -> slot 0x8")
    product["slots"][0x10] = lambda k: False
    check(model.dispatch_flag0_direct(product, b"k") ==
          ("try_again", 0x10),
          "flag0 direct slot 0x10 false -> try again")
    product["slots"][0x10] = lambda k: True
    check(model.dispatch_flag0_direct(product, b"k") ==
          ("ok", 0x10), "flag0 direct slot 0x10 true")
    product["slots"][0x10] = "canonical"
    check(model.dispatch_flag0_direct(product, b"k") ==
          ("ok", 0x08), "flag0 direct canonical -> slot 0x8")

    # Map find-or-insert (0x5f0e660): miss allocates, hit
    # returns the same value slot; a second key is separate.
    owner = model.fresh_owner()
    slot_a = model.map_find_or_insert(owner, b"key1", 4)
    slot_a[0] = "first"
    slot_b = model.map_find_or_insert(owner, b"key1", 4)
    check(slot_b is slot_a, "map hit returns the same slot")
    check(slot_b[0] == "first", "map hit keeps the value")
    slot_c = model.map_find_or_insert(owner, b"key2", 4)
    check(slot_c is not slot_a, "map miss allocates a new node")
    check(owner["map"]["count"] == 2, "map counts two nodes")

    # Shared_ptr install (type 0xf tail): big use ends at N.
    owner = model.fresh_owner(table_bits=2)
    check(model.install_shared(owner) == 4,
          "shared install N = 1 << d18")
    check(owner["big_use"] == 4, "shared install big use is N")
    check(len(owner["installed"]) == 4, "shared install N entries")
    check(all(e["small_use"] == 1 for e in owner["installed"]),
          "shared install small use is 1")
    check(owner["a60"] == 0, "shared install clears a60")

    # End to end, flag 0, canonical product, no filters.
    owner = model.fresh_owner()
    owner["products"][0xA50] = canonical_product()
    owner["products"][0xA58] = canonical_product()
    out = bytearray(b"\xab" * 16)
    args = insert_args()
    status, message, events = model.record_insert(
        owner, out, **args)
    check(status == "ok", "end-to-end flag 0 succeeds")
    check(message is None, "end-to-end no message")
    check(out[0:6] == bytes(6) and out[8:16] == bytes(8),
          "end-to-end out zeroed")
    check(out[6:8] == b"\xab\xab",
          "end-to-end out bytes 6..7 preserved")
    check("resolve" in events and "direct:0x8" in events,
          "end-to-end ran resolve and the direct arm")
    check("min_install" in events, "end-to-end ran min-install")
    check("once_resolver" in events, "end-to-end ran the tail")
    counters = args["counters"]
    check(counters["count"] == 0,
          "flag 0 never touches the caller counters")
    check(counters["total"] == 0,
          "flag 0 leaves the caller total at zero")
    check(owner["a70"] == 1 and
          owner["a68"] == model.key_total(b"key", b"val", 8),
          "flag 0 updates the owner counters")
    check(owner["a78"] == 0, "owner a78 not bumped for type 3")
    check(owner["c18"] == 42 and
          owner["c20"] == model.C20_SENTINEL,
          "end-to-end first install of the keypart")

    # End to end, flag 1: the caller counters move and the
    # owner counter fields do not.
    owner = model.fresh_owner()
    owner["products"][0xA50] = canonical_product()
    owner["products"][0xA58] = canonical_product()
    out = bytearray(16)
    args = insert_args(flag=1, context=object())
    status, message, events = model.record_insert(
        owner, out, **args)
    check(status == "ok", "end-to-end flag 1 succeeds")
    check("commit:0x38" in events, "flag 1 ran the commit")
    check("counters" in events, "flag 1 updated the counters")
    check(args["counters"]["count"] == 1,
          "flag 1 caller count is 1")
    check(args["counters"]["total"] ==
          model.key_total(b"key", b"val", 8),
          "flag 1 caller total is the key total")
    check(args["counters"]["typed"] == 1,
          "flag 1 caller typed for type 3")
    check(owner["a70"] == 0 and owner["a68"] == 0,
          "flag 1 never touches the owner counters")

    # End to end, type 0, 7 and 20 bump owner+0xa78 (bits 0,
    # 7, 20 of 0x100081); other types do not.
    for typ, want in ((0, 1), (7, 1), (3, 0), (16, 0), (17, 0),
                      (20, 1), (21, 0)):
        owner = model.fresh_owner()
        owner["products"][0xA50] = canonical_product()
        owner["products"][0xA58] = canonical_product()
        out = bytearray(16)
        model.record_insert(owner, out, **insert_args(typ=typ))
        check(owner["a78"] == want,
              "owner a78 for type %#x" % typ)

    # End to end, type 0xf installs the shared_ptr table.
    owner = model.fresh_owner(table_bits=1)
    owner["products"][0xA50] = canonical_product()
    owner["products"][0xA58] = canonical_product()
    out = bytearray(16)
    status, message, events = model.record_insert(
        owner, out, **insert_args(typ=0x0F, flag=1, context=object()))
    check(status == "ok", "end-to-end type 0xf succeeds")
    check("shared_install" in events, "type 0xf ran the install")
    check("mutex_lock" in events, "type 0xf flag 1 locks")
    check(owner["big_use"] == 2, "type 0xf big use is N")
    check(owner["ce8_locked"] is False, "mutex released after")
    owner = model.fresh_owner(table_bits=1)
    owner["products"][0xA50] = canonical_product()
    owner["products"][0xA58] = canonical_product()
    out = bytearray(16)
    status, message, events = model.record_insert(
        owner, out, **insert_args(typ=0x0F, flag=0))
    check("mutex_lock" not in events,
          "type 0xf flag 0 does not lock")
    check(owner["big_use"] == 2, "type 0xf flag 0 still installs")

    # End to end, flag 1 with a failing slot -> TryAgain,
    # and nothing after the commit runs.
    owner = model.fresh_owner()
    product = canonical_product()
    product["slots"][0x30] = lambda k, c: False
    owner["products"][0xA50] = product
    owner["products"][0xA58] = canonical_product()
    out = bytearray(16)
    args = insert_args(flag=1, context=object())
    status, message, events = model.record_insert(
        owner, out, **args)
    check(status == "try_again", "end-to-end try again on slot")
    check(message == model.TRY_AGAIN_MESSAGE,
          "try again message is key+seq exists")
    check("min_install" not in events,
          "try again skips the min-install")
    check(args["counters"]["count"] == 0,
          "try again skips the caller counters")
    check(owner["a70"] == 0, "try again skips the counters")

    # End to end, validate failure -> Corruption, code 2 in out.
    owner = model.fresh_owner()
    owner["products"][0xA50] = canonical_product()
    owner["products"][0xA58] = canonical_product()
    out = bytearray(16)
    status, message, events = model.record_insert(
        owner, out, **insert_args(protection=1))
    check(status == "corruption", "end-to-end corruption")
    check(message == b"ProtectionInfo mismatch",
          "end-to-end corruption message")
    check(out[0] == model.STATUS_CORRUPTION,
          "end-to-end corruption code in out")
    check("validate_fail" in events, "validate failure recorded")
    check(owner["a70"] == 0, "corruption skips the counters")

    # End to end, flag 0 with the +0xc78 filter gate: the map
    # path runs and a repeat insert finds the same node.
    owner = model.fresh_owner()
    owner["products"][0xA50] = canonical_product()
    owner["products"][0xA58] = canonical_product()
    owner["filter78_obj"] = {
        "slot_a0": lambda pair: True,
        "slot_98": lambda pair: (pair[0], pair[1]),
    }
    out = bytearray(16)
    status, message, events = model.record_insert(
        owner, out, **insert_args())
    check(status == "ok", "end-to-end map path succeeds")
    check("map:0x8" in events, "map path ran slot 0x8")
    check(owner["map"]["count"] == 1, "map path inserted one node")
    out = bytearray(16)
    status, message, events = model.record_insert(
        owner, out, **insert_args())
    check(owner["map"]["count"] == 1,
          "map path repeat insert finds the node")

    # End to end, the bloom filter: variant 1 via the slots,
    # variant 2 when *(owner+0x30) != 0.
    owner = model.fresh_owner()
    owner["products"][0xA50] = canonical_product()
    owner["products"][0xA58] = canonical_product()
    owner["filter_obj"] = {
        "slot_a0": lambda pair: True,
        "slot_98": lambda pair: (pair[0], pair[1]),
    }
    owner["filter_state"] = {"first": 0x1000, "probes": 2,
                             "words": {}}
    out = bytearray(16)
    status, message, events = model.record_insert(
        owner, out, **insert_args())
    check("bloom" in events, "bloom variant 1 ran")
    check("bloom2" not in events, "bloom variant 2 skipped")
    check(len(owner["filter_state"]["words"]) > 0,
          "bloom words were set")
    owner["c30"] = 1
    out = bytearray(16)
    status, message, events = model.record_insert(
        owner, out, **insert_args())
    check("bloom2" in events, "bloom variant 2 ran with c30")

    # A non-canonical product slot 0 supplies the buffer.
    owner = model.fresh_owner()
    seen = {}

    def slot0(out_slot, size):
        seen["size"] = size
        out_slot[0] = bytearray(size)

    product = canonical_product()
    product["slot0"] = slot0
    owner["products"][0xA50] = product
    owner["products"][0xA58] = canonical_product()
    out = bytearray(16)
    status, message, events = model.record_insert(
        owner, out, **insert_args())
    check(status == "ok", "non-canonical slot 0 still inserts")
    check(seen["size"] == model.key_total(b"key", b"val", 8),
          "slot 0 asked for the key total")

    print("ALL %d CHECKS PASSED" % CHECKS[0])


if __name__ == "__main__":
    main()
