"""Tests for the RE-001 type-22 delegate + serializer helper model (node #115).

Expectations are grounded in the binary: the pinned addresses, literals,
and branch rules in research/work-items/RE-001-type22-delegates-115/
records.json and the whole-function objdump excerpts there.
"""
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from type22_delegates_115 import (  # noqa: E402
    ARTIFACT_SHA256,
    DEREF_FLAG_MASK,
    FLAG_0X100,
    brace_wrap,
    delegate_decision,
    ends_with,
    resolve_field,
    slot12_emit,
    status_not_changeable,
    status_ok,
    string_compare,
)


def test_artifact_digest():
    assert ARTIFACT_SHA256 == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
    )


def test_resolve_field_deref_gate():
    store = {0x1008: "target-obj"}
    # flags 0x200 / 0x400 / 0x800 each deref once; no bit -> field address.
    for flags in (0x200, 0x400, 0x800, 0xE00):
        assert resolve_field(store, 0x1000, 0x8, flags) == "target-obj"
    assert resolve_field(store, 0x1000, 0x8, 0x100) == 0x1008
    assert resolve_field(store, 0x1000, 0x8, 0x0) == 0x1008
    # Null options-base -> null target.
    assert resolve_field(store, None, 0x8, 0xE00) is None
    assert resolve_field({0x1008: None}, 0x1000, 0x8, 0x200) is None
    with pytest.raises(KeyError):
        resolve_field({}, 0x1000, 0x8, 0x200)
    assert resolve_field({}, 0, 8, 0) is None
    assert resolve_field({}, 0x1000, 0xffffffff, 0) == 0xfff


def test_deref_flag_mask():
    assert DEREF_FLAG_MASK == 0xE00
    assert FLAG_0X100 == 0x100


def test_ends_with():
    assert ends_with("table_factory.id", ".id") is True
    assert ends_with("table_factory", ".id") is False
    assert ends_with(".id", ".id") is True
    assert ends_with("id", ".id") is False
    assert ends_with("", ".id") is False
    assert ends_with("x", "") is True


def test_string_compare_is_a_prefix_predicate():
    assert string_compare("abc", "abc") is True
    assert string_compare("abcd", "abc") is True
    assert string_compare("abc", "abd") is False
    assert string_compare("ab", "abc") is False
    assert string_compare("anything", "") is True
    assert string_compare(b"\xff\x00z", b"\xff\x00") is True
    assert string_compare("éclair", "é") is True


def test_slot12_emit():
    # Long path: all three gates pass.
    assert slot12_emit("", "bbt", ";", "opt=1", 0) == "id=bbt;opt=1"
    assert slot12_emit("pre;", "bbt", ";", "opt=1", 0) == "pre;id=bbt;opt=1"
    # config+0x28 == 1 -> bare id.
    assert slot12_emit("", "bbt", ";", "opt=1", 1) == "bbt"
    # Empty id -> bare id (empty).
    assert slot12_emit("", "", ";", "opt=1", 0) == ""
    # Empty nested options -> bare id (long-path emission skipped).
    assert slot12_emit("", "bbt", ";", "", 0) == "bbt"


def test_brace_wrap():
    assert brace_wrap("") == ""
    assert brace_wrap("id=bbt") == "{id=bbt}"
    assert brace_wrap("plain") == "plain"
    assert brace_wrap("a=b;c=d") == "{a=b;c=d}"
    assert brace_wrap("=") == "{=}"


def test_statuses():
    assert status_ok() == (0, "")
    code, msg = status_not_changeable("comparator")
    assert code == 4
    assert msg == "Option not changeable: comparator"


def _dec(**kw):
    base = dict(flags=0x100, config_plus4=0,
                name="table_factory", remaining_key="", value="",
                target_id="bbt")
    base.update(kw)
    return delegate_decision(**base)


def test_delegate_key_equals_name():
    kind, _ = _dec(remaining_key="table_factory")
    assert kind == "configure_slot10"


def test_delegate_key_is_id():
    kind, _ = _dec(remaining_key="id")
    assert kind == "configure_slot10"


def test_delegate_dot_id_match():
    kind, _ = _dec(name="table_factory.id", value="bbt")
    assert kind == "configure_slot10"


def test_delegate_dot_id_mismatch():
    kind, _ = _dec(name="table_factory.id", value="other")
    assert kind == "configure_slot10"


def test_delegate_empty_value_ok():
    kind, status = _dec(value="")
    assert kind == "ok"
    assert status == (0, "")


def test_delegate_id_prefix_mismatch_reaches_slot10():
    kind, _ = _dec(value="x", remaining_key="other.setting")
    assert kind == "configure_slot10"


def test_delegate_matching_prefix_with_equals():
    kind, _ = _dec(value="k=v", remaining_key="bbt.setting")
    assert kind == "set_via_equals"


def test_delegate_matching_prefix_without_equals():
    kind, _ = _dec(value="kv", remaining_key="bbt.setting")
    assert kind == "forward_no_equals"


def test_delegate_null_target_goes_slot10():
    kind, _ = _dec(value="x", target_is_null=True)
    assert kind == "configure_slot10"


def test_delegate_config_plus4_nonzero_target_null():
    # flags-0x100 clear, ConfigOptions+0x04 != 0, resolved target null.
    kind, status = _dec(flags=0, config_plus4=1, target_is_null=True, value="")
    assert kind == "ok" and status == (0, "")
    kind, (code, _) = _dec(flags=0, config_plus4=1, target_is_null=True,
                           value="x")
    assert kind == "error" and code == 4


def test_delegate_config_plus4_nonzero_target_present():
    kind, _ = _dec(flags=0, config_plus4=1, remaining_key="table_factory")
    assert kind == "configure_by_id"


def test_delegate_immutable_id_only_accepts_current_id():
    assert _dec(flags=0, config_plus4=1, name="field.id", value="bbt") == ("ok", (0, ""))
    assert _dec(flags=0, config_plus4=1, name="field.id", value="other")[0] == "error"


def test_delegate_immutable_unmatched_key_keeps_forwarder_boundary():
    assert _dec(flags=0, config_plus4=1, remaining_key="other", value="a=b")[0] == "forward_no_equals"
    assert _dec(flags=0, config_plus4=1, remaining_key="id", value="new")[0] == "configure_by_id"


def test_delegate_nested_prefix_accepts_longer_keys():
    assert _dec(remaining_key="bbt.setting.more", value="a=b")[0] == "set_via_equals"
    assert _dec(remaining_key="bb", value="a=b")[0] == "configure_slot10"
    assert _dec(name="field.id", value="")[0] == "configure_slot10"


def test_native_branch_bytes_pin_regression_contracts():
    binary = Path(__file__).resolve().parents[1] / "artifacts/node/115/hl-node"
    raw = binary.read_bytes()
    sites = {
        0x609a907: "0f857c020000",  # nested .id goes directly to slot10
        0x609aa1b: "84db0f8466010000",  # false starts_with goes to slot10
        0x609aab4: "4d85ed",  # immutable null test uses resolved r13 target
        0x609b09f: "0f840bfdffff",  # immutable id key joins id comparison
        0x61d1410: "85d2751c",  # nonzero memcmp returns false
        0x61d142b: "85db0f94c0",  # zero min-length minus prefix-length returns true
    }
    for address, value in sites.items():
        expected = bytes.fromhex(value)
        assert raw[address - 0x1000:address - 0x1000 + len(expected)] == expected
