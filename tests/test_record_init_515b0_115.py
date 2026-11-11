"""Tests for tools/record_init_515b0_115.py.

Each test drives the initializer model end to end and checks the
observable initial field values, not only constants. Run directly:
every test_* function is invoked by the packet checker (pytest is
not installed on this VM).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from record_init_515b0_115 import (  # noqa: E402
    GAPS, MIN_SIZE, SCALAR_WRITES, ZERO_BLOCKS, Record,
    established_offsets,
)


def _fresh():
    record = Record(base=0x100000)
    assert record.init() is None
    return record


def test_self_pointers_point_at_own_fields():
    record = _fresh()
    for field, target in ((0x08, 0x18), (0x28, 0x38), (0xB0, 0xA0),
                          (0xB8, 0xA0), (0x138, 0x148), (0x160, 0x170)):
        assert record.read(field, 8) == record.base + target


def test_scalar_zero_fields():
    record = _fresh()
    for offset, width, value in SCALAR_WRITES:
        if value == 0:
            assert record.read(offset, width) == 0


def test_zero_blocks_are_all_zero():
    record = _fresh()
    for base in ZERO_BLOCKS:
        assert record.read(base, 16) == 0


def test_short_string_triples_read_empty():
    record = _fresh()
    for at, buf in ((0x08, 0x18), (0x28, 0x38), (0x138, 0x148)):
        pointer, size, first = record.short_string(at)
        assert pointer == record.base + buf
        assert size == 0
        assert first == 0


def test_empty_range_pairs():
    record = _fresh()
    assert record.read(0xB0, 8) == record.read(0xB8, 8)
    assert record.read(0xB0, 8) == record.base + 0xA0
    assert record.read(0x160, 8) == record.base + 0x170
    assert record.read(0x168, 8) == 0
    assert record.mem[0x170] == 0


def test_gaps_are_never_claimed():
    established = set(established_offsets())
    for start, end in GAPS:
        for offset in range(start, end):
            assert offset not in established
            assert not _fresh().is_established(offset)


def test_init_restores_dirtied_established_fields():
    record = _fresh()
    for offset in established_offsets():
        record.mem[offset] = 0xFF
    record.init()
    for offset in established_offsets():
        assert record.mem[offset] != 0xFF


def test_init_leaves_gap_bytes_untouched():
    record = Record(base=0x100000)
    for start, end in GAPS:
        for offset in range(start, end):
            record.mem[offset] = 0xAB
    record.init()
    for start, end in GAPS:
        for offset in range(start, end):
            assert record.mem[offset] == 0xAB


def test_minimum_size_covers_highest_write():
    assert MIN_SIZE == 0x171
    assert max(established_offsets()) == 0x170


def test_init_writes_no_other_offsets():
    record = _fresh()
    assert set(record.mem) == set(established_offsets())
