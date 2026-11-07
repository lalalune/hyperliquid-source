"""Tests for the node #115 options-map host model (0x609e510)."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from options_map_host_e510_115 import (
    EMPTY_PATH,
    GATE_FAIL,
    INVALID_ARGUMENT,
    NULL_OBJECT,
    OK,
    PROCEED,
    SharedPtr,
    base_predicate,
    configure_host,
    copy_config,
    id_configure_helper,
    merge_maps,
    merge_maps_hash_path,
    name_gate,
    parse_kv_text,
    release_helper,
)

DEFAULT = "<default-name>"
OPTS = {"flag_u32": 1, "flag_u8": 0, "delimiter": "; ",
        "sanity": 255, "readahead": 524288}


def obj(**kw):
    base = {"id": "myid", "name": "MyOptions", "nickname": None,
            "slot16_override": None}
    base.update(kw)
    return base


def serialize_ok(opts_copy):
    assert opts_copy["delimiter"] == ";"
    return OK, "a=1;b=2"


def serialize_fail(opts_copy):
    return INVALID_ARGUMENT, ""


def test_empty_name_clears_map():
    # Empty name: out_name erased, caller map cleared, kOk.
    status, out, m, note = configure_host(
        "", OPTS, obj(), {"a": "1"}, DEFAULT, serialize_ok, parse_kv_text)
    assert (status, out, m, note) == (OK, "", {}, EMPTY_PATH)


def test_default_name_is_empty():
    # A name equal to the .bss default is treated as empty.
    status, out, m, note = configure_host(
        DEFAULT, OPTS, obj(), {"a": "1"}, DEFAULT,
        serialize_ok, parse_kv_text)
    assert (status, out, m, note) == (OK, "", {}, EMPTY_PATH)


def test_null_object_uses_empty_id():
    # Null object: the helper runs with an empty id string.
    status, out, m, note = configure_host(
        "opt", OPTS, None, {"a": "1"}, DEFAULT,
        serialize_ok, parse_kv_text)
    assert status == OK and note == NULL_OBJECT
    # "opt" has no '=': out_name = the input itself.
    assert out == "opt"


def test_helper_plain_name_resolves_to_itself():
    status, out, m = id_configure_helper("opt", "myid", {}, DEFAULT)
    assert (status, out, m) == (OK, "opt", {})


def test_helper_empty_input_gives_id():
    status, out, m = id_configure_helper("", "myid", {"k": "v"}, DEFAULT)
    assert (status, out) == (OK, "myid")
    assert m == {"k": "v"}


def test_helper_map_with_id_key():
    # Parses into the caller map, 'id' erased, others survive.
    status, out, m = id_configure_helper(
        "id=other;x=1", "myid", {"pre": "0"}, DEFAULT)
    assert status == OK and out == "other"
    assert m == {"pre": "0", "x": "1"}


def test_helper_map_no_id_keeps_id_and_entries():
    status, out, m = id_configure_helper(
        "x=1;y=2", "myid", {}, DEFAULT)
    assert status == OK and out == "myid"
    assert m == {"x": "1", "y": "2"}


def test_helper_map_no_id_empty_id_clears():
    status, out, m = id_configure_helper("x=1", "", {"pre": "0"}, DEFAULT)
    assert (status, out, m) == (OK, "x=1", {})


def test_helper_parse_failure_clears():
    status, out, m = id_configure_helper("x;y=2", "myid", {"pre": "0"}, DEFAULT)
    assert (status, out, m) == (OK, "x;y=2", {})


def test_helper_id_value_is_default_truncates():
    status, out, m = id_configure_helper(
        "id=" + DEFAULT + ";x=1", "myid", {}, DEFAULT)
    assert (status, out) == (OK, "")
    assert m == {"x": "1"}


def test_base_predicate():
    assert base_predicate("", "MyOptions", None) is False
    assert base_predicate("MyOptions", "MyOptions", None) is True
    assert base_predicate("Nick", "MyOptions", "Nick") is True
    assert base_predicate("Other", "MyOptions", "Nick") is False
    assert base_predicate("Nick", "MyOptions", None) is False


def test_name_gate_base_path():
    assert name_gate("MyOptions", "MyOptions", None) is True
    assert name_gate("Nick", "MyOptions", "Nick") is True
    assert name_gate("Other", "MyOptions", "Nick") is False
    assert name_gate("", "MyOptions", None) is False
    # A null NickName() can only fail the gate, never pass it.
    assert name_gate("Nick", "MyOptions", None) is False


def test_name_gate_override():
    # An overriding slot 16 decides by itself.
    assert name_gate("Other", "MyOptions", None, True) is True
    assert name_gate("MyOptions", "MyOptions", None, False) is False


def test_gate_failure_is_silent():
    # Gate failure: kOk, the map is untouched, nothing serializes.
    seen = []
    status, out, m, note = configure_host(
        "Other", OPTS, obj(), {"a": "1"}, DEFAULT,
        lambda o: seen.append(o) or (OK, "a=1"), parse_kv_text)
    assert (status, out, m, note) == (OK, "Other", {"a": "1"}, GATE_FAIL)
    assert seen == []


def test_delimiter_forced_to_semicolon():
    copied = copy_config(OPTS)
    assert copied["delimiter"] == ";"
    assert copied["sanity"] == 255 and copied["readahead"] == 524288


def test_serialize_error_propagates():
    status, out, m, note = configure_host(
        "MyOptions", OPTS, obj(), {"a": "1"}, DEFAULT,
        serialize_fail, parse_kv_text)
    assert status == INVALID_ARGUMENT and note == "serialize error"
    assert m == {"a": "1"}


def test_parse_error_propagates():
    def bad_parse(text):
        return INVALID_ARGUMENT, {}, "Mismatched key value pair, '=' expected"
    status, out, m, note = configure_host(
        "MyOptions", OPTS, obj(), {"a": "1"}, DEFAULT,
        serialize_ok, bad_parse)
    assert status == INVALID_ARGUMENT and note == "parse error"
    assert m == {"a": "1"}


def test_merge_insert_if_absent():
    merged, inserted = merge_maps({"a": "old", "c": "3"}, {"a": "new", "b": "2"})
    assert merged == {"a": "old", "c": "3", "b": "2"}
    assert inserted == ["b"]


def test_merge_paths_agree():
    caller = {f"k{i}": str(i) for i in range(25)}
    parsed = {"k0": "new", "fresh": "1"}
    assert merge_maps(caller, parsed) == merge_maps_hash_path(caller, parsed)


def test_parse_duplicate_key_last_wins():
    status, entries, _ = parse_kv_text("a=1;a=2")
    assert (status, entries) == (OK, {"a": "2"})


def test_parse_errors():
    assert parse_kv_text("abc")[0] == INVALID_ARGUMENT
    assert parse_kv_text("abc")[2] == "Mismatched key value pair, '=' expected"
    assert parse_kv_text("a;b=2")[2] == "Unexpected char in key"
    assert parse_kv_text(";a=1")[2] == "Unexpected char in key"
    assert parse_kv_text("=1")[2] == "Empty key found"
    assert parse_kv_text("{a=1;b=2}")[1] == {"a": "1", "b": "2"}


def test_shared_ptr_release_paths():
    # Combined use=1, weak=1: inline dispose + destroy.
    assert SharedPtr(1, 1).release_after_copy(False) == ["dispose", "destroy"]
    # Plain decrement to zero: the release helper runs.
    assert SharedPtr(1, 2).release_after_copy(False) == ["release-helper"]
    # Plain decrement staying above zero: nothing happens.
    assert SharedPtr(3, 1).release_after_copy(False) == []
    # The release helper itself: dispose, weak--, destroy at zero.
    assert release_helper(SharedPtr(0, 1)) == ["dispose", "destroy"]
    assert release_helper(SharedPtr(0, 2)) == ["dispose"]


def test_end_to_end_proceed():
    # name == the object's Name(): serialize, parse, merge.
    status, out, m, note = configure_host(
        "MyOptions", OPTS, obj(), {"a": "old"}, DEFAULT,
        serialize_ok, parse_kv_text)
    assert (status, out, note) == (OK, "MyOptions", PROCEED)
    assert m == {"a": "old", "b": "2"}


def test_end_to_end_id_prefixed_name():
    # "id=MyOptions" resolves out_name to the object's name, then proceeds.
    status, out, m, note = configure_host(
        "id=MyOptions", OPTS, obj(), {}, DEFAULT,
        serialize_ok, parse_kv_text)
    assert (status, out, note) == (OK, "MyOptions", PROCEED)
    assert m == {"a": "1", "b": "2"}
