"""Tests for the node #115 parse-then-apply wrapper model (RE-001)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from parse_then_apply_wrapper_115 import (
    INVALID_ARGUMENT,
    NOT_FOUND,
    OK,
    Status,
    apply_loop,
    parse_kv_text,
    parse_then_apply,
)

TYPE_INFO = {
    "max_open_files": {"offset": 0x40, "type": 1, "verification": 0},
    "create_if_missing": {"offset": 0x00, "type": 1, "verification": 0},
    "rate_limiter": {"offset": 0x10, "type": 26, "verification": 4},
}


def test_empty_input_is_ok_and_applies_nothing():
    st, applied, ov, destroyed = parse_then_apply("", TYPE_INFO)
    assert st.ok and st.code == OK
    assert applied == {} and destroyed is True


def test_plain_pair_applies():
    st, applied, ov, destroyed = parse_then_apply("max_open_files=100", TYPE_INFO)
    assert st.ok
    assert applied == {"max_open_files": "100"}
    assert destroyed is True


def test_braced_input_is_unwrapped():
    st, applied, ov, destroyed = parse_then_apply("{max_open_files=100;create_if_missing=true}", TYPE_INFO)
    assert st.ok
    assert applied == {"max_open_files": "100", "create_if_missing": "true"}


def test_duplicate_key_last_wins():
    st, applied, ov, destroyed = parse_then_apply("max_open_files=1;max_open_files=2", TYPE_INFO)
    assert st.ok
    assert applied == {"max_open_files": "2"}


def test_parse_error_propagates_verbatim_and_applies_nothing():
    st, applied, ov, destroyed = parse_then_apply("max_open_files", TYPE_INFO)
    assert st.code == INVALID_ARGUMENT
    assert st.message == "Mismatched key value pair, '=' expected"
    assert applied == {}
    assert destroyed is True


def test_parse_error_on_later_segment_discards_earlier_pairs():
    st, applied, ov, destroyed = parse_then_apply("max_open_files=1;noequals", TYPE_INFO)
    assert st.code == INVALID_ARGUMENT
    assert applied == {}


def test_unexpected_char_in_key():
    st, applied, ov, destroyed = parse_then_apply("a;b=2", TYPE_INFO)
    assert st.code == INVALID_ARGUMENT
    assert st.message == "Unexpected char in key"
    assert applied == {}


def test_empty_key():
    st, applied, ov, destroyed = parse_then_apply("=1", TYPE_INFO)
    assert st.code == INVALID_ARGUMENT
    assert st.message == "Empty key found"


def test_verification_4_entry_is_skipped():
    st, applied, ov, destroyed = parse_then_apply("rate_limiter=x", TYPE_INFO)
    assert st.ok
    assert applied == {}


def test_unknown_key_diverts_into_overflow_map():
    overflow = {}
    st, applied, ov, destroyed = parse_then_apply(
        "max_open_files=1;custom_opt=zzz", TYPE_INFO, overflow=overflow)
    assert st.ok
    assert applied == {"max_open_files": "1"}
    assert ov == {"custom_opt": "zzz"}


def test_unknown_key_errors_when_overflow_is_null():
    st, applied, ov, destroyed = parse_then_apply(
        "max_open_files=1;custom_opt=zzz", TYPE_INFO, overflow=None)
    assert st.code == NOT_FOUND
    assert st.message == "Unrecognized optioncustom_opt"
    assert applied == {"max_open_files": "1"}


def test_unknown_key_skipped_when_options_base_byte_is_nonzero():
    st, applied, ov, destroyed = parse_then_apply(
        "custom_opt=zzz", TYPE_INFO, options_base_first_byte=1, overflow=None)
    assert st.ok
    assert applied == {}


def test_null_arg5_faults_on_value_parse_path():
    st, applied, ov, destroyed = parse_then_apply(
        "max_open_files=1", TYPE_INFO, arg5=None)
    assert st.code == NOT_FOUND
    assert st.message == "Could not find optionmax_open_files"
    assert applied == {}


def test_null_arg5_does_not_fault_for_verification_4():
    st, applied, ov, destroyed = parse_then_apply(
        "rate_limiter=x", TYPE_INFO, arg5=None)
    assert st.ok


def test_apply_stops_at_first_failure_keeping_earlier_applies():
    st, applied, ov, destroyed = parse_then_apply(
        "max_open_files=1;custom_opt=zzz;create_if_missing=true",
        TYPE_INFO, overflow=None)
    assert st.code == NOT_FOUND
    assert applied == {"max_open_files": "1"}


def test_parse_kv_text_matches_pinned_algorithm():
    st, entries = parse_kv_text("a=1;b=2")
    assert st.ok and entries == {"a": "1", "b": "2"}
    st, entries = parse_kv_text("  { a=1 }  ")
    assert st.ok and entries == {"a": "1"}
