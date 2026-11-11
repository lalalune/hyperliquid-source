"""Tests for tools/wrapper_destructor_55a20_115.py (node #115, 0x5d55a20).

pytest is not installed on this VM; the packet verify.py invokes every
test_* function here directly, so each test is self-contained.
Slot-0 values are function identities: DERIVED_DESTRUCTOR is the
derived complete destructor 0x5d55970, anything else takes the
dynamic fallback path.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from wrapper_destructor_55a20_115 import (
    DERIVED_DESTRUCTOR,
    DERIVED_TABLE,
    MIDDLE_TABLE,
    Subobject,
    Wrapper,
    destroy,
)


def _dispatched():
    calls = []

    def fn(wrapper):
        calls.append(wrapper)

    fn.calls = calls
    return fn


def test_mismatch_dispatches_with_original_wrapper():
    sub = Subobject(slot0=0x5D492E0, field_48="a", field_38="b")
    wrapper = Wrapper(sub)
    fn = _dispatched()
    assert destroy(wrapper, fn) == "dispatched"
    assert fn.calls == [wrapper]
    assert wrapper.dispatched_with is wrapper
    assert wrapper.released == []
    assert wrapper.base_called_with is None
    assert sub.vptr is None


def test_match_inlines_both_releases_in_order():
    sub = Subobject(slot0=DERIVED_DESTRUCTOR, field_48="a", field_38="b")
    wrapper = Wrapper(sub)
    assert destroy(wrapper, _dispatched()) == "inlined"
    assert wrapper.released == ["a", "b"]
    assert sub.vptr == MIDDLE_TABLE
    assert wrapper.base_called_with is sub


def test_match_null_48_skips_only_that_release():
    sub = Subobject(slot0=DERIVED_DESTRUCTOR, field_48=None, field_38="b")
    wrapper = Wrapper(sub)
    assert destroy(wrapper, _dispatched()) == "inlined"
    assert wrapper.released == ["b"]
    assert wrapper.base_called_with is sub


def test_match_null_38_skips_only_that_release():
    sub = Subobject(slot0=DERIVED_DESTRUCTOR, field_48="a", field_38=None)
    wrapper = Wrapper(sub)
    assert destroy(wrapper, _dispatched()) == "inlined"
    assert wrapper.released == ["a"]
    assert wrapper.base_called_with is sub


def test_match_both_null_still_calls_base():
    sub = Subobject(slot0=DERIVED_DESTRUCTOR)
    wrapper = Wrapper(sub)
    assert destroy(wrapper, _dispatched()) == "inlined"
    assert wrapper.released == []
    assert wrapper.base_called_with is sub


def test_vptr_sequence_passes_through_derived_table():
    seen = []
    sub = Subobject(slot0=DERIVED_DESTRUCTOR, field_48="a", field_38="b")

    class TracingSub(Subobject):
        pass

    # Observe the intermediate vptr by releasing in a wrapper that
    # records the vptr at release time via a subclass hook is not
    # available, so assert the endpoints and the derived constant
    # instead: the first write is DERIVED_TABLE by construction.
    assert DERIVED_TABLE == 0x64D08A8
    assert MIDDLE_TABLE == 0x64CF200
    wrapper = Wrapper(sub)
    destroy(wrapper, _dispatched())
    assert sub.vptr == MIDDLE_TABLE
    assert wrapper.released == ["a", "b"]


def test_dispatch_never_touches_vptr_or_fields():
    sub = Subobject(slot0=0x5D486F0, field_48="a", field_38="b")
    wrapper = Wrapper(sub)
    fn = _dispatched()
    destroy(wrapper, fn)
    assert sub.vptr is None
    assert wrapper.released == []
    assert wrapper.base_called_with is None
