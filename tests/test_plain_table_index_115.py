"""Tests for tools/plain_table_index_115.py (RE-001, node #115).

The hash tests compare the model against an independent literal
transcription of the disassembly at 0x61c34a0 written in this file
(different loop shape and word assembly from the model), plus
hand-computed anchors. The remaining tests check the model against
target-grounded expectations: exact serialized bytes, exact
ToString text, boundary values and corruption controls.
"""

import math
import os
import random
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from plain_table_index_115 import (
    ChunkedStore,
    Histogram,
    PlainTableIndex,
    bucket_index,
    hex_encode,
    load_boundaries,
    rocksdb_hash,
    varint_encode,
    varint_len,
)

BOUNDARIES_PATH = os.path.join(
    os.path.dirname(__file__), "..", "research", "work-items",
    "RE-001-plain-table-index-115", "boundaries.tsv")

MIX = 0xC6A4A793
MASK = 0xFFFFFFFF


def hash_transcription(data, seed=397):
    """Independent transcription of the disassembly at 0x61c34a0.

    h = (len * 0xc6a4a793) ^ seed; word loop adds each little-endian
    4-byte word then mixes with >> 16; the tail sign-extends each
    remaining byte at shifts 16/8/0 then mixes with >> 24; a length
    that is a multiple of 4 returns with no final mix.
    """
    h = ((len(data) * MIX) & MASK) ^ seed
    pos = 0
    end = len(data) - (len(data) % 4)
    while pos < end:
        word = (data[pos] | (data[pos + 1] << 8)
                | (data[pos + 2] << 16) | (data[pos + 3] << 24))
        h = (h + word) & MASK
        mixed = (h * MIX) & MASK
        h = mixed ^ (mixed >> 16)
        pos += 4
    rem = len(data) - pos
    if rem == 3:
        h = (h + ((data[pos + 2] - 256 if data[pos + 2] >= 0x80
                   else data[pos + 2]) << 16)) & MASK
        h = (h + ((data[pos + 1] - 256 if data[pos + 1] >= 0x80
                   else data[pos + 1]) << 8)) & MASK
        h = (h + (data[pos] - 256 if data[pos] >= 0x80
                  else data[pos])) & MASK
        mixed = (h * MIX) & MASK
        h = mixed ^ (mixed >> 24)
    elif rem == 2:
        h = (h + ((data[pos + 1] - 256 if data[pos + 1] >= 0x80
                   else data[pos + 1]) << 8)) & MASK
        h = (h + (data[pos] - 256 if data[pos] >= 0x80
                  else data[pos])) & MASK
        mixed = (h * MIX) & MASK
        h = mixed ^ (mixed >> 24)
    elif rem == 1:
        h = (h + (data[pos] - 256 if data[pos] >= 0x80
                  else data[pos])) & MASK
        mixed = (h * MIX) & MASK
        h = mixed ^ (mixed >> 24)
    return h


def varint_decode(buf, pos=0):
    value = 0
    shift = 0
    while True:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7


# ---------------------------------------------------------------- hash

def test_hash_empty_is_seed():
    # len % 4 == 0 returns h with no final mix: (0 * m) ^ 397 == 397.
    assert rocksdb_hash(b"", 397) == 397
    assert rocksdb_hash(b"", 0) == 0


@pytest.mark.parametrize("data,expected", [
    (b"abcd", 0x0C6F6BE9),
    (b"\x00", 0x1820F522),
    (b"\xff", 0x517C4DF6),
])
def test_hash_hand_anchors(data, expected):
    assert rocksdb_hash(data, 397) == expected
    assert hash_transcription(data, 397) == expected


def test_hash_matches_transcription_on_corpus():
    rng = random.Random(115)
    cases = [b"", b"a", b"ab", b"abc", b"abcd", b"abcde",
             b"\x00" * 8, b"\xff" * 7, b"\x80\x81\xfe\xffabc",
             b"chain_ext.rs", b"rocksdb"]
    cases += [bytes(rng.randrange(256) for _ in range(n))
              for n in range(0, 41)]
    cases += [bytes(rng.randrange(256) for _ in range(100))]
    for data in cases:
        assert rocksdb_hash(data, 397) == hash_transcription(data, 397)
        assert rocksdb_hash(data, 0) == hash_transcription(data, 0)
        assert rocksdb_hash(data, 12345) == hash_transcription(data, 12345)


def test_hash_sign_extension_matters():
    # A 0xff tail byte contributes -1, not 255: the two must differ.
    assert rocksdb_hash(b"\xff", 397) != rocksdb_hash(b"\x01", 397)
    assert rocksdb_hash(b"a\xff", 397) == hash_transcription(b"a\xff", 397)


def test_hash_word_boundary():
    # Lengths 3, 4, 5 exercise tail, no-tail and tail-after-word.
    for data in (b"abc", b"abcd", b"abcde", b"abcdefg", b"abcdefgh"):
        assert rocksdb_hash(data, 397) == hash_transcription(data, 397)


# ---------------------------------------------------------------- varint

@pytest.mark.parametrize("value,expected", [
    (0, b"\x00"), (127, b"\x7f"), (128, b"\x80\x01"),
    (300, b"\xac\x02"), (16383, b"\xff\x7f"), (16384, b"\x80\x80\x01"),
    (2097151, b"\xff\xff\x7f"), (2097152, b"\x80\x80\x80\x01"),
    (268435455, b"\xff\xff\xff\x7f"), (268435456, b"\x80\x80\x80\x80\x01"),
    (0xFFFFFFFF, b"\xff\xff\xff\xff\x0f"),
])
def test_varint_encode(value, expected):
    assert varint_encode(value) == expected
    assert varint_len(value) == len(expected)
    decoded, pos = varint_decode(expected)
    assert (decoded, pos) == (value, len(expected))


def test_varint_len_boundaries():
    assert varint_len(0x7F) == 1 and varint_len(0x80) == 2
    assert varint_len(0x3FFF) == 2 and varint_len(0x4000) == 3
    assert varint_len(0x1FFFFF) == 3 and varint_len(0x200000) == 4
    assert varint_len(0xFFFFFFF) == 4 and varint_len(0x10000000) == 5


# ---------------------------------------------------------------- hex

def test_hex_encode():
    assert hex_encode(b"abc", 0) == b"abc"
    assert hex_encode(b"", 0) == b""
    assert hex_encode(b"\x00\xff\xab", 1) == b"00FFAB"
    assert hex_encode(b"\x0a\x1b", 2) == b"0A1B"


# ---------------------------------------------------------------- bucket index

def test_bucket_index_boundaries():
    boundaries = load_boundaries(BOUNDARIES_PATH)
    assert len(boundaries) == 109
    assert boundaries[0] == 1 and boundaries[-1] == 13000000000000000000
    assert bucket_index(0, boundaries) == 0
    # lower_bound: the first boundary >= the value (1 is boundaries[0]).
    assert bucket_index(1, boundaries) == 0
    assert bucket_index(2, boundaries) == 1
    assert bucket_index(3, boundaries) == 2
    assert bucket_index(13000000000000000000 - 1, boundaries) == 108
    assert bucket_index(13000000000000000000, boundaries) == 108
    assert bucket_index(2 ** 64 - 1, boundaries) == 108


def test_bucket_index_small_table():
    table = [1, 2, 10]
    assert bucket_index(0, table) == 0
    assert bucket_index(1, table) == 0
    assert bucket_index(2, table) == 1
    assert bucket_index(9, table) == 2
    assert bucket_index(10, table) == 2


# ---------------------------------------------------------------- histogram

def test_histogram_empty():
    boundaries = [1, 2, 10]
    hist = Histogram(boundaries)
    assert hist.min == 10 and hist.max == 0 and hist.count == 0
    assert hist.average() == 0.0 and hist.stddev() == 0.0
    assert hist.median() == 0.0 and hist.percentile(99.0) == 0.0
    assert hist.to_string() == (
        "Count: 0 Average: 0.0000  StdDev: 0.00\n"
        "Min: 0  Median: 0.0000  Max: 0\n"
        "Percentiles: P50: 0.00 P75: 0.00 P99: 0.00 P99.9: 0.00 P99.99: 0.00\n"
        + "-" * 54 + "\n")


def test_histogram_record_and_stats():
    boundaries = [1, 2, 10]
    hist = Histogram(boundaries)
    for value in (0, 0, 5):
        hist.record(value)
    assert hist.count == 3 and hist.sum == 5 and hist.sum_of_squares == 25
    assert hist.min == 0 and hist.max == 5
    assert hist.buckets == [2, 0, 1]
    assert hist.average() == pytest.approx(5.0 / 3.0)
    assert hist.stddev() == pytest.approx(math.sqrt(50.0 / 9.0))
    assert hist.median() == pytest.approx(0.75)
    assert hist.percentile(75.0) == pytest.approx(4.0)
    assert hist.percentile(99.0) == pytest.approx(5.0)


def test_histogram_to_string_exact():
    boundaries = [1, 2, 10]
    hist = Histogram(boundaries)
    for value in (0, 0, 5):
        hist.record(value)
    assert hist.to_string() == (
        "Count: 3 Average: 1.6667  StdDev: 2.36\n"
        "Min: 0  Median: 0.7500  Max: 5\n"
        "Percentiles: P50: 0.75 P75: 4.00 P99: 5.00 P99.9: 5.00 P99.99: 5.00\n"
        + "-" * 54 + "\n"
        + "[       0,       1 ]        2  66.667%  66.667% "
        + "#" * 13 + "\n"
        + "(       2,      10 ]        1  33.333% 100.000% "
        + "#" * 7 + "\n")


def test_histogram_percentile_exact_boundary_skips_empty_bucket():
    # Records 0 and 5: P50 threshold is exactly 1.0, the cumulative
    # count at bucket 0. The binary walks while running <= threshold,
    # so it passes bucket 0 and the empty bucket 1 and lands in
    # bucket 2, where the fraction is 0: the value is bucket 2's
    # lower boundary (2), not bucket 0's upper edge (1).
    boundaries = [1, 2, 10]
    hist = Histogram(boundaries)
    hist.record(0)
    hist.record(5)
    assert hist.percentile(50.0) == pytest.approx(2.0)


def test_histogram_percentile_past_last_returns_max():
    boundaries = [1, 2, 10]
    hist = Histogram(boundaries)
    hist.record(9)
    assert hist.percentile(100.0) == pytest.approx(9.0)


# ---------------------------------------------------------------- chunked store

def test_chunked_store_growth():
    store = ChunkedStore(entries_per_chunk=2)
    for i in range(5):
        store.append(100 + i, i)
    assert store.total() == 5
    assert [len(chunk) for chunk in store.chunks] == [2, 2, 1]
    assert [e.arg4 for e in store.entries()] == [0, 1, 2, 3, 4]
    assert [e.hash for e in store.entries()] == [100, 101, 102, 103, 104]


# ---------------------------------------------------------------- owner end to end

def _small_index(**kwargs):
    boundaries = load_boundaries(BOUNDARIES_PATH)
    return PlainTableIndex(boundaries, entries_per_chunk=4, **kwargs)


def test_record_key_runs_and_histogram():
    idx = _small_index()
    idx.record_key(b"a", 10)
    idx.record_key(b"a", 11)
    idx.record_key(b"a", 12)
    idx.record_key(b"b", 20)
    # Only two distinct keys: two entries, total_keys counts distinct
    # arrivals, run lengths 0 (first key) and 3 (three a's) recorded.
    assert idx.total_keys == 2
    assert idx.run_length == 1
    assert idx.store.total() == 2
    assert [e.arg4 for e in idx.store.entries()] == [10, 20]
    assert [e.hash for e in idx.store.entries()] == [
        rocksdb_hash(b"a", 397), rocksdb_hash(b"b", 397)]
    assert idx.histogram.count == 2
    assert sorted(idx.histogram.buckets[i] for i in range(109)
                  if idx.histogram.buckets[i]) == [1, 1]
    assert idx.histogram.min == 0 and idx.histogram.max == 3


def test_record_key_first_empty_key_is_unchanged():
    # The stored key starts empty, so the first empty key takes the
    # unchanged path: no entry, no histogram sample, just the counter.
    idx = _small_index()
    idx.record_key(b"", 5)
    assert idx.store.total() == 0
    assert idx.total_keys == 0
    assert idx.run_length == 1
    idx.record_key(b"x", 6)
    assert idx.store.total() == 1
    assert idx.total_keys == 1
    assert idx.histogram.count == 1  # the finished run length (1)


def test_record_key_sample_interval_reappends():
    idx = _small_index(sample_interval=2)
    idx.record_key(b"a", 10)
    idx.record_key(b"a", 11)
    idx.record_key(b"a", 12)
    # After the second a the run length hits 2 (a multiple of the
    # interval), so the third a re-appends the stored hash.
    assert idx.store.total() == 2
    assert [e.arg4 for e in idx.store.entries()] == [10, 12]
    assert idx.store.entries()[1].hash == rocksdb_hash(b"a", 397)


def test_record_key_flag_758_direct_path():
    idx = _small_index()
    idx.record_key(b"a", 10)
    idx.flag_758 = True  # input flag: the binary never sets it here
    idx.record_key(b"a", 11)
    # Direct path: no compare, no run-length record, main body only.
    assert idx.total_keys == 2
    assert idx.histogram.count == 1  # only the first key's 0 sample
    assert idx.store.total() == 2
    assert idx.flag_758 is False  # the counter path clears it


def test_compute_bucket_count():
    idx = _small_index()
    assert idx.compute_bucket_count() == 1  # gate 0 forces 1
    idx.bucket_gate = 1
    assert idx.compute_bucket_count() == 1  # ratio 0.0 forces 1
    idx.ratio = 2.0
    idx.total_keys = 5
    assert idx.compute_bucket_count() == 3  # int(5 * 0.5) + 1
    idx.ratio = -1.0
    assert idx.compute_bucket_count() == 1


def test_dump_empty_index_exact_bytes():
    idx = _small_index()
    buf = idx.dump()
    # [varint 1 bucket][varint 0 keys][slot 0x7fffffff]; no suffix.
    assert buf == b"\x01\x00" + (0x7FFFFFFF).to_bytes(4, "little")
    assert idx.bucket_count == 1 and idx.suffix_size == 0
    assert idx.histogram.count == 1  # the final run length (0)
    assert idx.log_records[0][0] == 1  # histogram log, level 1
    assert idx.log_records[0][1].startswith(
        "[table/plain/plain_table_index.cc:101] "
        "Number of Keys per prefix Histogram: Count: 1")
    assert idx.log_records[1] == (
        0, "[table/plain/plain_table_index.cc:156] "
           "Reserving 0 bytes for plain table's sub_index")
    assert idx.log_records[2] == (
        0, "[table/plain/plain_table_index.cc:202] "
           "hash table size: 1, suffix_map length 0")


def test_dump_single_bucket_exact_bytes():
    idx = _small_index()
    idx.record_key(b"a", 10)
    idx.record_key(b"a", 11)
    idx.record_key(b"b", 20)
    buf = idx.dump()
    # One bucket holding both entries: slot = suffix offset | 0x80000000,
    # suffix = varint(2) + arg4s in insertion order (10, 20).
    expected = (b"\x01\x02" + (0x80000000).to_bytes(4, "little")
                + b"\x02" + (10).to_bytes(4, "little")
                + (20).to_bytes(4, "little"))
    assert buf == expected
    assert idx.suffix_size == 9
    assert idx.histogram.count == 3  # run samples 0, 3, then final 1
    assert idx.log_records[2] == (
        0, "[table/plain/plain_table_index.cc:202] "
           "hash table size: 1, suffix_map length 9")


def _parse_serialized(buf):
    """Re-parse a serialized index the way a reader would."""
    bucket_count, pos = varint_decode(buf, 0)
    key_count, pos = varint_decode(buf, pos)
    slots = [int.from_bytes(buf[pos + i * 4: pos + i * 4 + 4], "little")
             for i in range(bucket_count)]
    pos += bucket_count * 4
    suffix = buf[pos:]
    recovered = {}
    for slot in slots:
        if slot == 0x7FFFFFFF:
            continue
        if slot & 0x80000000:
            off = slot & 0x7FFFFFFF
            count, off = varint_decode(suffix, off)
            values = [int.from_bytes(suffix[off + j * 4: off + j * 4 + 4],
                                     "little") for j in range(count)]
            recovered.setdefault("multi", []).append(values)
        else:
            recovered.setdefault("single", []).append(slot)
    return bucket_count, key_count, slots, recovered


def test_dump_round_trip_recovers_arg4s():
    idx = _small_index(bucket_gate=1, ratio=0.5)
    keys = [b"alpha", b"beta", b"gamma", b"delta", b"alpha", b"epsilon"]
    for i, key in enumerate(keys):
        idx.record_key(key, 100 + i)
    buf = idx.dump()
    bucket_count, key_count, slots, recovered = _parse_serialized(buf)
    assert bucket_count == idx.bucket_count
    assert key_count == 6  # six arrivals; alpha recorded twice (not in a row)
    singles = recovered.get("single", [])
    multis = recovered.get("multi", [])
    seen = singles + [v for group in multis for v in group]
    assert sorted(seen) == sorted(
        e.arg4 for e in idx.store.entries())
    # Every multi-entry bucket's suffix lists values in insertion order.
    entries = idx.store.entries()
    for group in multis:
        assert group == sorted(group, key=lambda a: next(
            j for j, e in enumerate(entries) if e.arg4 == a))


def test_dump_multi_bucket_slots():
    idx = _small_index(bucket_gate=1, ratio=0.25)
    for i, key in enumerate([b"a", b"b", b"c", b"d", b"e", b"f"]):
        idx.record_key(key, i)
    buf = idx.dump()
    # ratio 0.25, 6 keys -> int(6 * 4.0) + 1 = 25 buckets.
    assert idx.bucket_count == 25
    bucket_count, key_count, slots, _ = _parse_serialized(buf)
    assert bucket_count == 25 and key_count == 6
    assert len(slots) == 25
    assert all(s == 0x7FFFFFFF for s in slots
               if s not in [e.arg4 for e in idx.store.entries()]
               and not s & 0x80000000)
    # Slots agree with the gather: hash % 25 decides the bucket.
    for entry in idx.store.entries():
        bucket = entry.hash % 25
        slot = slots[bucket]
        if slot != 0x7FFFFFFF and not slot & 0x80000000:
            assert slot == entry.arg4


def test_dump_allocator_callback_receives_total():
    seen = []

    def allocate(total):
        seen.append(total)
        return bytearray(total)

    idx = _small_index(allocate=allocate)
    idx.record_key(b"a", 1)
    idx.record_key(b"b", 2)
    buf = idx.dump()
    assert seen == [len(buf)]
    assert len(buf) == 1 + 1 + 4 + 9
