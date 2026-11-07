"""Tests for the RE-001 type-22 delegate + serializer helper model (node #115).

Expectations are grounded in the binary: the pinned addresses, literals,
and branch rules in research/work-items/RE-001-type22-delegates-115/
records.json and the whole-function objdump excerpts there.
"""
import sys
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
    # Deref of a missing cell -> null target (field holds nullptr).
    assert resolve_field({}, 0x1000, 0x8, 0x200) is None


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


def test_string_compare():
    assert string_compare("abc", "abc") == 0
    assert string_compare("abc", "abd") < 0
    assert string_compare("abd", "abc") > 0
    assert string_compare("ab", "abc") < 0
    assert string_compare("abc", "ab") > 0
    assert string_compare("", "") == 0
    assert string_compare("a", "") > 0
    # Memcmp decides before the length: "b" > "aa" on the first byte.
    assert string_compare("b", "aa") > 0


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
    base = dict(flags=0x100, config_plus4=0, object_is_null=False,
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
    assert kind == "configure_by_id"


def test_delegate_dot_id_mismatch():
    kind, (code, msg) = _dec(name="table_factory.id", value="other")
    assert kind == "error"
    assert code == 4
    assert msg == "Option not changeable: table_factory.id"


def test_delegate_empty_value_ok():
    kind, status = _dec(value="")
    assert kind == "ok"
    assert status == (0, "")


def test_delegate_id_prefix_match():
    kind, _ = _dec(value="x", id_prefix_matches=True)
    assert kind == "configure_slot10"


def test_delegate_id_prefix_mismatch_equals():
    kind, _ = _dec(value="k=v", id_prefix_matches=False, value_has_equals=True)
    assert kind == "set_via_equals"


def test_delegate_id_prefix_mismatch_no_equals():
    kind, _ = _dec(value="kv", id_prefix_matches=False, value_has_equals=False)
    assert kind == "forward_no_equals"


def test_delegate_null_target_goes_slot10():
    kind, _ = _dec(value="x", target_is_null=True)
    assert kind == "configure_slot10"


def test_delegate_config_plus4_nonzero_object_null():
    # flags-0x100 clear, ConfigOptions+0x04 != 0, object null.
    kind, status = _dec(flags=0, config_plus4=1, object_is_null=True, value="")
    assert kind == "ok" and status == (0, "")
    kind, (code, _) = _dec(flags=0, config_plus4=1, object_is_null=True,
                           value="x")
    assert kind == "error" and code == 4


def test_delegate_config_plus4_nonzero_object_present():
    kind, _ = _dec(flags=0, config_plus4=1, object_is_null=False)
    assert kind == "configure_slot10"
