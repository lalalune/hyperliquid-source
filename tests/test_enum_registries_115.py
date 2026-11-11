"""Tests for the node #115 named-enum registries (RE-001).

Every expectation is grounded in the evidence packet
research/work-items/RE-001-enum-registries-115/ (records.json and
registries.tsv, both derived from the static initializer 0x60c78a0
and the builders it calls).
"""

import sys
import runpy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from enum_registries_115 import (  # noqa: E402
    FIELD_BYTES, HASH_SEED, HASH_THRESHOLD, ORDERED, TYPES, UNORDERED,
    parse, serialize, usable_compressions,
)


def test_parse_every_registered_name():
    for option_type, (name, address, _) in TYPES.items():
        for entry_name, value in UNORDERED[address].items():
            assert parse(option_type, entry_name) == value, (
                f"type {option_type} {entry_name}")


def test_parse_rejects_unknown_names():
    for option_type in TYPES:
        assert parse(option_type, "kDoesNotExist") is None
        assert parse(option_type, "") is None
    # Case-sensitive: the helpers compare size then memcmp.
    assert parse(16, "kplain") is None
    assert parse(16, "KPlain") is None


def test_serialize_every_value():
    for option_type, (name, address, _) in TYPES.items():
        for entry_name, value in UNORDERED[address].items():
            assert serialize(option_type, value) == entry_name, (
                f"type {option_type} value {value}")


def test_serialize_rejects_unknown_values():
    for option_type in TYPES:
        assert serialize(option_type, 0xFE) is None
        assert serialize(option_type, 0x100) is None


def test_round_trip():
    for option_type, (name, address, _) in TYPES.items():
        for entry_name, value in UNORDERED[address].items():
            assert serialize(option_type, parse(option_type,
                                                entry_name)) == entry_name
            assert parse(option_type,
                         serialize(option_type, value)) == value


def test_map_and_unordered_agree():
    # Each reverse map duplicates one forward map exactly.
    pairs = [("0x65071a0", "0x6506fe0"), ("0x65071e0", "0x6507020"),
             ("0x6507220", "0x6507060"), ("0x6507260", "0x65070a0")]
    for map_addr, unordered_addr in pairs:
        assert ORDERED[map_addr] == {v: k for k, v in
                                     UNORDERED[unordered_addr].items()}


def test_compression_anomaly_as_built():
    # The initializer writes 64 and 255; the upstream header says 8
    # and 64.  The model pins the as-built values.
    assert parse(13, "kZSTDNotFinalCompression") == 64
    assert parse(13, "kDisableCompressionOption") == 255
    assert serialize(13, 64) == "kZSTDNotFinalCompression"
    assert serialize(13, 255) == "kDisableCompressionOption"
    # 8 is not a CompressionType value in the as-built registry.
    assert serialize(13, 8) is None


def test_usable_compressions_filter():
    # 0x5d85480 keeps values 1..254: it skips kNoCompression (0) and
    # kDisableCompressionOption (255) -- the binary's own code treats
    # 0xff as the disable sentinel.
    names = usable_compressions()
    assert "kNoCompression" not in names
    assert "kDisableCompressionOption" not in names
    assert "kZSTDNotFinalCompression" in names
    assert len(names) == 8


def test_type_14_field_width():
    # Only CompactionStopStyle (type 14) is stored as a 4-byte field;
    # its parse helper stores and its serialize case compares 4 bytes.
    assert FIELD_BYTES[14] == 4
    assert all(FIELD_BYTES[t] == 1 for t in TYPES if t != 14)


def test_parse_threshold_and_seed():
    # The parse helpers switch to the hash path above 20 elements
    # with seed 0xc70f6907; every registry here is at most 10 entries.
    assert HASH_THRESHOLD == 20
    assert HASH_SEED == 0xC70F6907
    assert max(len(r) for r in UNORDERED.values()) == 10


def test_registry_inventory():
    assert len(UNORDERED) == 8
    assert len(ORDERED) == 4
    assert sum(len(r) for r in UNORDERED.values()) == 34
    assert sum(len(r) for r in ORDERED.values()) == 15


def test_excerpt_implicit_segment_spellings():
    path = Path(__file__).resolve().parent.parent / "research/work-items/RE-001-enum-registries-115/verify.py"
    normalize = runpy.run_path(str(path))["normalized_excerpt"]
    for old, new in [("rep stos %eax,%es:(%rdi)", "rep stos %eax,(%rdi)"),
                     ("rep movsb %ds:(%rsi),%es:(%rdi)", "rep movsb (%rsi),(%rdi)")]:
        assert normalize("10:\tf3 ab\t" + old) == normalize("10:\tf3 ab\t" + new)


def test_excerpt_comparison_retains_instruction_bytes_and_operands():
    path = Path(__file__).resolve().parent.parent / "research/work-items/RE-001-enum-registries-115/verify.py"
    normalize = runpy.run_path(str(path))["normalized_excerpt"]
    original = "10:\tf3 ab\trep stos %eax,%es:(%rdi)"
    assert normalize(original) != normalize(original.replace("f3 ab", "f3 aa"))
    assert normalize(original) != normalize(original.replace("%eax", "%rax"))
