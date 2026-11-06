"""Tests for tools/hashlinklist_insert_115.py.

The hash vectors are cross-checked by an independent second
transcription of 0x61c38a0 written directly from the disassembly
in this file (reference_hash64); the model and the reference must
agree on every length class. The hash has no executable oracle on
this VM (no cargo/rustc, no harness for the node binary), so the
two transcriptions plus the byte-for-byte excerpt check in the
packet's verify.py are the grounding; both were written from the
same disassembly and are stated as such.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

import pytest

from hashlinklist_insert_115 import (
    ChainExhausted,
    CountNode,
    HashLinkListRep,
    IndexNode,
    Record,
    compare_records,
    decode_varint32,
    encode_varint32,
    hash64,
    hex_encode,
    identity_transform,
    run_transform_chain,
)

MASK = (1 << 64) - 1


def _mum(a, b):
    p = (a & MASK) * (b & MASK)
    return p & MASK, (p >> 64) & MASK


def _fin(x):
    y = (x ^ (x >> 37)) & MASK
    z = (y * 0x165667B19E3779F9) & MASK
    return (z ^ (z >> 32)) & MASK


def reference_hash64(data):
    """Independent transcription of 0x61c38a0, written from the
    disassembly (not imported from the model)."""
    n = len(data)
    if n > 128:
        raise ValueError("len > 128")
    if n == 0:
        return 0x5342C3010FE1DD04
    r64 = lambda o: int.from_bytes(data[o:o + 8], "little")
    r32 = lambda o: int.from_bytes(data[o:o + 4], "little")
    if n <= 3:
        v = (data[0] | (n << 24) | (data[n // 2] << 8)
             | (data[n - 1] << 16)) ^ 0x396CFEB8
        return _fin((v * 0x9E3779B185EBCA87) & MASK)
    if n <= 8:
        pre = (((r32(n - 4) << 32) | r32(0)) ^ 0xBE4BA423396CFEB8) & MASK
        t = pre ^ (pre >> 51)
        t = (t * 0x9E3779B1) & MASK
        t = (t + n) & MASK
        u = t ^ (t >> 47)
        return _fin((u * 0xC2B2AE3D27D4EB4F) & MASK)
    if n <= 16:
        a = r64(0) ^ 0xBE4BA423396CFEB8
        b = r64(n - 8) ^ 0x1CAD21F72C81017C
        lo, hi = _mum((a + n) & MASK, b)
        return _fin((a + n + b + (lo ^ hi)) & MASK)
    seed = (n * 0x9E3779B185EBCA87) & MASK
    if n > 96:
        lo1, hi1 = _mum(r64(0x30) ^ 0x3F349CE33F76FAA8,
                        r64(0x38) ^ 0x1D4F0BC7C7BBDCF9)
        lo2, hi2 = _mum(r64(n - 0x40) ^ 0x3159B4CD4BE0518A,
                        r64(n - 0x38) ^ 0x647378D9C97E9FC8)
        seed = (seed + (lo1 ^ hi1) + (lo2 ^ hi2)) & MASK
    if n > 64:
        lo1, hi1 = _mum(r64(0x20) ^ 0xCB00C391BB52283C,
                        r64(0x28) ^ 0xA32E531B8B65D088)
        lo2, hi2 = _mum(r64(n - 0x30) ^ 0x4EF90DA297486471,
                        r64(n - 0x28) ^ 0xD8ACDEA946EF1938)
        seed = (seed + (lo1 ^ hi1) + (lo2 ^ hi2)) & MASK
    if n > 32:
        lo1, hi1 = _mum(r64(0x10) ^ 0x78E5C0CC4EE679CB,
                        r64(0x18) ^ 0x2172FFCC7DD05A82)
        lo2, hi2 = _mum(r64(n - 0x20) ^ 0x8E2443F7744608B8,
                        r64(n - 0x18) ^ 0x4C263A81E69035E0)
        seed = (seed + (lo1 ^ hi1) + (lo2 ^ hi2)) & MASK
    lo1, hi1 = _mum(r64(8) ^ 0x1CAD21F72C81017C, r64(0) ^ 0xBE4BA423396CFEB8)
    lo2, hi2 = _mum(r64(n - 8) ^ 0x1F67B3B7A4A44072,
                    r64(n - 16) ^ 0xDB979083E96DD4DE)
    return _fin(((hi1 ^ lo1) + (hi2 ^ lo2) + seed) & MASK)


# ---------------------------------------------------------------- varint32

@pytest.mark.parametrize("value", [0, 1, 63, 127, 128, 300, 16383, 16384,
                                   2 ** 21 - 1, 2 ** 28 - 1])
def test_varint32_round_trip(value):
    enc = encode_varint32(value)
    assert len(enc) <= 5
    got, end = decode_varint32(enc)
    assert (got, end) == (value, len(enc))


def test_varint32_single_byte_fast_path():
    # A byte with the high bit clear is the value itself; the host
    # takes this path without calling the decoder.
    assert decode_varint32(bytes([0x05])) == (5, 1)
    assert decode_varint32(bytes([0x7F])) == (0x7F, 1)


def test_varint32_limit_failure():
    # Truncated varint at the 5-byte limit: the decoder returns 0
    # and leaves the out slot untouched (the host pre-zeroes it).
    buf = bytes([0x80, 0x80, 0x80, 0x80, 0x80])
    assert decode_varint32(buf, 0, 5) == (0, 0)
    # Start already at the limit.
    assert decode_varint32(buf, 5, 5) == (0, 5)


def test_varint32_shift_cap():
    # Five continuation bytes push the shift past 28: failure.
    buf = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    assert decode_varint32(buf, 0, 5) == (0, 0)
    # Four continuation bytes plus a terminal byte succeeds: the
    # shift reaches exactly 28, which is not past the cap.
    assert decode_varint32(bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x7F]), 0, 5) == (
        0x7FFFFFFFF, 5)


def test_record_encoding():
    rec = Record(b"hello")
    assert rec.encoded == encode_varint32(5) + b"hello"
    value, end = decode_varint32(rec.encoded, 0, 5)
    assert (value, end) == (5, 1)
    assert rec.encoded[end:] == b"hello"


# ---------------------------------------------------------------- hash64

@pytest.mark.parametrize("length", [0, 1, 2, 3, 4, 5, 8, 9, 15, 16, 17,
                                    24, 32, 33, 48, 64, 65, 80, 96, 97,
                                    112, 128])
def test_hash64_matches_reference(length):
    data = bytes((i * 37 + 11) & 0xFF for i in range(length))
    assert hash64(data) == reference_hash64(data)


def test_hash64_empty_constant():
    assert hash64(b"") == 0x5342C3010FE1DD04


def test_hash64_deterministic_and_spread():
    a = hash64(b"rocksdb")
    b = hash64(b"rocksdb")
    c = hash64(b"rocksdb!")
    assert a == b and a != c
    assert 0 <= a <= MASK


def test_hash64_over_128_is_boundary():
    with pytest.raises(ValueError):
        hash64(bytes(129))


# ---------------------------------------------------------------- hex encode

def test_hex_encode_uppercase():
    assert hex_encode(bytes([0x00, 0xFF, 0x10, 0xAB])) == b"00FF10AB"
    assert hex_encode(b"") == b""


def test_hex_encode_raw_copy():
    assert hex_encode(bytes([0x00, 0xFF]), uppercase=False) == bytes([0x00, 0xFF])


# ---------------------------------------------------------------- transform chain

def test_chain_level_arithmetic():
    seen = {}

    def terminal(pair):
        seen["pair"] = pair
        return pair

    key = bytes(range(24))
    # One canonical hop, then the terminal at index 1: it receives
    # (key, len - 8*2).
    assert run_transform_chain([None, terminal], key) == (key, 8)
    assert seen["pair"] == (key, 8)
    # Terminal first: it receives (key, len - 8).
    assert run_transform_chain([terminal], key) == (key, 16)
    # Three canonical hops then the terminal: len - 8*4.
    long_key = bytes(range(40))
    assert run_transform_chain([None, None, None, terminal], long_key) == (
        long_key, 8)


def test_chain_identity_reference():
    key = bytes(range(24))
    out, length = run_transform_chain([None, identity_transform], key)
    assert (out, length) == (key, 8)


def test_chain_exhausted():
    with pytest.raises(ChainExhausted):
        run_transform_chain([None, None], b"0123456789abcdef")


def test_chain_thirteen_hop_unrolling():
    # The host unrolls 13 hops before calling the 13th node's slot;
    # the model walks the list, which is observationally identical.
    seen = {}

    def terminal(pair):
        seen["pair"] = pair
        return pair

    key = bytes(200)
    nodes = [None] * 13 + [terminal]
    run_transform_chain(nodes, key)
    assert seen["pair"] == (key, 200 - 8 * 14)


# ---------------------------------------------------------------- insert end to end

def _rep(**kw):
    kw.setdefault("transform_nodes", [identity_transform])
    return HashLinkListRep(bucket_count=1, **kw)


def _chain(rep, bucket=0):
    head = rep.buckets[bucket]
    out = []
    if isinstance(head, IndexNode):
        return [r.key for r in head.index]
    node = head.next if isinstance(head, CountNode) else head
    while node is not None:
        out.append(node.key)
        node = node.next
    return out


def test_insert_empty_bucket_then_wrap():
    rep = _rep()
    r1 = Record(b"aaa")
    assert rep.insert(r1) == ("empty-bucket", 0)
    assert rep.buckets[0] is r1 and r1.next is None
    r2 = Record(b"bbb")
    assert rep.insert(r2) == ("linked", 0)
    head = rep.buckets[0]
    assert isinstance(head, CountNode) and head.count == 2
    assert _chain(rep) == [b"aaa", b"bbb"]


def test_insert_ordered_splice():
    rep = _rep()
    for key in (b"mmm", b"aaa", b"zzz", b"bbb"):
        rep.insert(Record(key))
    assert _chain(rep) == [b"aaa", b"bbb", b"mmm", b"zzz"]


def test_insert_convert_threshold():
    rep = _rep(convert_threshold=3)
    paths = [rep.insert(Record(k)) for k in (b"a", b"b", b"c", b"d")]
    assert paths == [("empty-bucket", 0), ("linked", 0), ("linked", 0),
                     ("converted", 0)]
    head = rep.buckets[0]
    assert isinstance(head, IndexNode) and head.count == 4
    assert [r.key for r in head.index] == [b"a", b"b", b"c", b"d"]
    assert rep.insert(Record(b"e")) == ("sub-index-insert", 0)
    assert head.count == 5
    assert [r.key for r in head.index] == [b"a", b"b", b"c", b"d", b"e"]


def test_insert_log_threshold():
    seen = []

    def sink(bucket, count, hex_key):
        seen.append((bucket, count, hex_key))

    rep = _rep(convert_threshold=3, log_threshold=2, log_sink=sink)
    rep.insert(Record(b"a"))
    rep.insert(Record(b"b"))
    # Third insert: pre-insert count 2 == log threshold 2, so the
    # log fires with the hex-encoded key, then the insert proceeds.
    rep.insert(Record(b"key42"))
    assert seen == [(0, 2, b"6B65793432")]
    # The fourth insert converts (pre-insert count 3 == threshold).
    assert rep.insert(Record(b"d")) == ("converted", 0)


def test_insert_log_disabled_when_threshold_nonpositive():
    seen = []
    rep = _rep(convert_threshold=3, log_threshold=0,
               log_sink=lambda *a: seen.append(a))
    for k in (b"a", b"b", b"c", b"d"):
        rep.insert(Record(k))
    assert seen == []


def test_bucket_index_uses_transformed_key():
    # With a canonical hop before the terminal, the transformed
    # length is 8 shorter, so the hash (and usually the bucket)
    # differs from the no-hop chain.
    key = bytes(range(32))
    rep_plain = HashLinkListRep(bucket_count=64,
                                transform_nodes=[identity_transform])
    rep_hop = HashLinkListRep(bucket_count=64,
                              transform_nodes=[None, identity_transform])
    b_plain, t_plain = rep_plain._bucket_index(key)
    b_hop, t_hop = rep_hop._bucket_index(key)
    # _bucket_index returns the transformed key bytes, already
    # sliced to the transformed length: len - 8*1 / len - 8*2.
    assert t_plain == key[:24]
    assert t_hop == key[:16]
    # The two transformed keys hash differently, so the bucket
    # selection differs in general; the exact bucket is checked
    # against the multiply-high formula below.
    assert hash64(t_plain) != hash64(t_hop)
    # Bucket is (count * hash) >> 64.
    h = hash64(t_plain)
    assert b_plain == ((64 * h) >> 64)


def test_bucket_spread():
    rep = HashLinkListRep(bucket_count=16,
                          transform_nodes=[identity_transform])
    # 16-byte keys: the terminal receives them at length 8, so the
    # hash input is non-empty (an 8-byte key would transform to
    # length 0 and hash to the empty constant).
    buckets = {rep._bucket_index(bytes([i]) * 16)[0] for i in range(32)}
    assert len(buckets) > 1


def test_convert_threshold_clamped_to_three():
    rep = _rep(convert_threshold=1)
    assert rep.convert_threshold == 3
