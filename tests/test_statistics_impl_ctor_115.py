"""Tests for the node #115 StatisticsImpl construction model.

Run under pytest when available, or plain python3 (the __main__
runner below) — pytest is not installed on the author's VM.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from statistics_impl_ctor_115 import (  # noqa: E402
    BASE_VTABLE,
    BUCKET_ARRAY_BASE,
    BUCKET_COUNT_FIELD,
    HISTOGRAM_VTABLE,
    NOOP_DTOR,
    RECORDS_PER_SHARD,
    RECORD_MUTEX,
    RECORD_STRIDE,
    SHARD_HEADER,
    SHARD_STRIDE,
    SHARD_TAIL,
    STATISTICS_VTABLE,
    alloc_size,
    alloc_size_overflows,
    allocator_return,
    bucket_array_end,
    bucket_array_fits,
    bucket_count,
    bucket_count_value,
    bucket_exponent,
    builder_release_reachable,
    ctor_fields,
    ctor_record_name,
    destroy_order,
    destroyer_skips,
    mutex_ok,
    shard_record_addresses,
    shared_init_writes,
)


def test_bucket_exponent():
    assert bucket_exponent(0) == 3  # hardware_concurrency unknown
    assert bucket_exponent(1) == 3
    assert bucket_exponent(8) == 3
    assert bucket_exponent(9) == 4  # 16 >= 9
    assert bucket_exponent(16) == 4
    assert bucket_exponent(17) == 5  # 32 >= 17
    assert bucket_exponent(32) == 5
    assert bucket_exponent(33) == 6
    assert bucket_exponent(64) == 6
    assert bucket_exponent(1024) == 10


def test_bucket_count():
    assert bucket_count(0) == 8
    assert bucket_count(8) == 8
    assert bucket_count(9) == 16
    assert bucket_count(17) == 32
    assert bucket_count(1024) == 1024


def test_alloc_size():
    assert alloc_size(8) == 8 * 0xCE40 + 0x40 == 0x67240
    assert alloc_size(16) == 16 * 0xCE40 + 0x40
    assert alloc_size(1) == 0xCE40 + 0x40


def test_alloc_size_overflows():
    assert not alloc_size_overflows(0x9EE009EE009E)
    assert alloc_size_overflows(0x9EE009EE009E + 1)
    assert not alloc_size_overflows(1024)


def test_shard_layout_arithmetic():
    # 53 records of 0x3c8 fill shard+0x598 .. shard+0xce00 exactly.
    assert RECORDS_PER_SHARD == 53
    assert SHARD_HEADER + RECORDS_PER_SHARD * RECORD_STRIDE == 0xCE00
    assert 0xCE00 + SHARD_TAIL == SHARD_STRIDE
    assert SHARD_STRIDE == 0xCE40


def test_shard_record_addresses():
    addrs = shard_record_addresses(0x1000, 2)
    assert len(addrs) == 106
    assert addrs[0] == 0x1000 + 0x598
    assert addrs[52] == 0x1000 + 0xCA38  # last record of shard 0
    assert addrs[53] == 0x1000 + 0xCE40 + 0x598  # first of shard 1
    assert addrs[-1] == 0x1000 + 0xCE40 + 0xCA38
    assert all(b - a == RECORD_STRIDE for a, b in zip(addrs[:52], addrs[1:52]))


def test_destroy_order():
    order = destroy_order(0x1000, 2)
    assert len(order) == 106
    assert order[0] == 0x1000 + 0xCE40 + 0xCA38  # last shard, last record
    assert order[52] == 0x1000 + 0xCE40 + 0x598  # last shard, first record
    assert order[53] == 0x1000 + 0xCA38  # first shard, last record
    assert order[-1] == 0x1000 + 0x598
    assert set(order) == set(shard_record_addresses(0x1000, 2))


def test_builder_release_dead():
    assert builder_release_reachable() is False


def test_shared_init_writes():
    writes = dict(shared_init_writes(0xABCDEF, 3))
    assert writes[0x08] == 0xABCDEF  # min pointer
    assert writes[0x10] == 0
    assert writes[0x18] == 0
    assert writes[0x20] == 0
    assert writes[0x28] == 0
    # bucket first-qwords at rec+0x30, +0x58, +0x80
    assert writes[0x30] == 0
    assert writes[0x58] == 0
    assert writes[0x80] == 0
    assert len(shared_init_writes(0x1, 0)) == 5  # count 0: no buckets


def test_bucket_count_value():
    assert bucket_count_value(0x1000, 0x1000 + 8 * 20) == 20
    assert bucket_count_value(0x1000, 0x1000) == 0


def test_bucket_array_fits():
    assert bucket_array_end(22) == 0x30 + 22 * 0x28 == 0x3A0
    assert bucket_array_fits(22) is True
    assert bucket_array_fits(23) is False  # would reach the mutex
    assert bucket_array_fits(20) is True


def test_ctor_fields():
    fields = ctor_fields(0x1111, 0x2222)
    assert fields[0] == (0x00, STATISTICS_VTABLE)
    assert fields[1] == (0x20, 3)  # level byte
    assert (0x28, 0x1111) in fields
    assert (0x30, 0x2222) in fields
    assert STATISTICS_VTABLE == 0x64D2D88
    assert HISTOGRAM_VTABLE == 0x64D2B80
    assert BASE_VTABLE == 0x64D3430
    assert BUCKET_COUNT_FIELD == 0x398
    assert RECORD_MUTEX == 0x3A0


def test_ctor_record_name():
    assert ctor_record_name() == "StatisticsOptions"
    assert len(ctor_record_name()) == 17
    assert ctor_record_name().startswith("StatisticsOption")


def test_mutex_ok():
    assert mutex_ok(0) is True
    assert mutex_ok(16) is True
    assert mutex_ok(110) is True
    assert mutex_ok(1) is False
    assert mutex_ok(22) is False


def test_allocator_return():
    assert allocator_return(0, 0xDEAD) == 0xDEAD
    assert allocator_return(12, 0xDEAD) is None  # ENOMEM -> NULL
    assert allocator_return(22, 0xDEAD) is None  # EINVAL -> NULL


def test_destroyer_skips():
    assert destroyer_skips(NOOP_DTOR) is True
    assert destroyer_skips(0x5D8B3B0) is False


def test_packet_records_digest():
    here = os.path.dirname(os.path.abspath(__file__))
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-statistics-impl-ctor-115", "records.json")
    records = json.load(open(packet))
    assert records["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    assert records["windows"]["builder"]["start"] == "0x60716d0"
    assert records["windows"]["builder"]["end"] == "0x6071952"
    assert records["windows"]["ctor"]["start"] == "0x6071a00"
    assert records["record_vtable"]["typeinfo_name"] == (
        "N7rocksdb13HistogramImplE")
    assert records["statisticsimpl_vtable"]["typeinfo_name"] == (
        "N7rocksdb14StatisticsImplE")
    assert records["builder_behavior"]["old_store_release"]["reachable"] is False
    assert len(records["record_vtable"]["slots"]) == 16
    assert records["record_vtable"]["slots"][0]["target"] == "0x5d89570"
    assert records["record_vtable"]["slots"][2]["target"] == "0x606b0c0"


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_")]

if __name__ == "__main__":
    for fn in TESTS:
        fn()
        print("PASS", fn.__name__)
    print("ALL %d TESTS PASSED" % len(TESTS))
