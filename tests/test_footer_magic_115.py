"""Tests for the node #115 footer magic model
(tools/footer_magic_115.py).

Runnable with pytest, or by invoking each test_* function directly.
"""

from tools.footer_magic_115 import (
    BLOCK_CURRENT,
    BLOCK_LEGACY,
    CUCKOO_CANDIDATE,
    PAIR2_CURRENT,
    PAIR2_WRITTEN,
    build_footer,
    decode_gate,
    encode_block_handle,
)


def test_encode_block_handle_varint_pair():
    assert encode_block_handle(0, 0) == b"\x00\x00"
    assert encode_block_handle(300, 47) == b"\xac\x02\x2f"
    assert encode_block_handle(0xFFFFFFFF, 1) == b"\xff\xff\xff\xff\x0f\x01"


def test_build_legacy_form_layout_and_length():
    footer = build_footer(0, 0, BLOCK_CURRENT, (0x1000, 0x200), (0x3000, 0x40))
    assert len(footer) == 48
    handles = encode_block_handle(0x1000, 0x200) + encode_block_handle(0x3000, 0x40)
    assert footer[:len(handles)] == handles
    assert footer[len(handles):40] == bytes(40 - len(handles))


def test_build_legacy_substitutes_block_magic():
    footer = build_footer(0, 0, BLOCK_CURRENT, (0, 0), (0, 0))
    assert int.from_bytes(footer[40:48], "little") == BLOCK_LEGACY


def test_build_legacy_substitutes_pair2_magic():
    footer = build_footer(0, 0, PAIR2_CURRENT, (0, 0), (0, 0))
    assert int.from_bytes(footer[40:48], "little") == PAIR2_WRITTEN


def test_build_legacy_keeps_unknown_candidate():
    footer = build_footer(0, 0, 0x1122334455667788, (0, 0), (0, 0))
    assert int.from_bytes(footer[40:48], "little") == 0x1122334455667788


def test_build_versioned_form_layout():
    footer = build_footer(3, 2, BLOCK_CURRENT, (0x10, 0x20), (0x30, 0x40))
    assert len(footer) == 53
    assert footer[0] == 2
    handles = encode_block_handle(0x10, 0x20) + encode_block_handle(0x30, 0x40)
    assert footer[1:1 + len(handles)] == handles
    assert footer[1 + len(handles):41] == bytes(41 - 1 - len(handles))
    assert int.from_bytes(footer[41:45], "little") == 3
    # No substitution in the versioned form.
    assert int.from_bytes(footer[45:53], "little") == BLOCK_CURRENT


def test_build_versioned_keeps_cuckoo_candidate():
    footer = build_footer(1, 0, CUCKOO_CANDIDATE, (0, 0), (0, 0))
    assert int.from_bytes(footer[45:53], "little") == CUCKOO_CANDIDATE
    assert int.from_bytes(footer[41:45], "little") == 1


def test_gate_accepts_legacy_and_normalizes():
    assert decode_gate(BLOCK_LEGACY, 0) == (True, BLOCK_CURRENT, 5, "decode48")
    assert decode_gate(BLOCK_LEGACY, BLOCK_CURRENT) == (
        True, BLOCK_CURRENT, 5, "decode48")


def test_gate_rejects_legacy_for_other_expectations():
    assert decode_gate(BLOCK_LEGACY, PAIR2_CURRENT)[0] is False
    assert decode_gate(BLOCK_LEGACY, BLOCK_LEGACY)[0] is False


def test_gate_accepts_pair2_written_and_normalizes():
    assert decode_gate(PAIR2_WRITTEN, 0) == (True, PAIR2_CURRENT, 0, "decode48")
    assert decode_gate(PAIR2_WRITTEN, PAIR2_CURRENT) == (
        True, PAIR2_CURRENT, 0, "decode48")
    assert decode_gate(PAIR2_WRITTEN, BLOCK_CURRENT)[0] is False


def test_gate_stores_current_and_expected_values_unchanged():
    assert decode_gate(BLOCK_CURRENT, BLOCK_CURRENT) == (
        True, BLOCK_CURRENT, None, "decode_current")
    assert decode_gate(0x1122334455667788, 0x1122334455667788) == (
        True, 0x1122334455667788, 0, "decode48_versioned")


def test_gate_no_expectation_accepts_arbitrary_trailing():
    assert decode_gate(0xDEADBEEFCAFEF00D, 0) == (
        True, 0xDEADBEEFCAFEF00D, 0, "decode48_versioned")


def test_gate_rejects_mismatch_with_specific_expectation():
    assert decode_gate(0xDEADBEEFCAFEF00D, BLOCK_CURRENT) == (
        False, None, None, "error")
    assert decode_gate(PAIR2_CURRENT, PAIR2_CURRENT)[0] is True
