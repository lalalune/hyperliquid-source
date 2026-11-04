"""Tests for the node #115 selector-inversion wrapper 0x5ebd130 (RE-001).

Run from the clone root: python3 tests/test_selector_inversion_wrapper_115.py
(pytest is not installed on this VM, so the file runs under plain python3
via its __main__ runner, like the earlier RE-001 items.)
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from selector_inversion_wrapper_115 import selector_inversion_wrapper

MASK64 = (1 << 64) - 1

CHECKS = []


def check(name, cond):
    CHECKS.append(name)
    if not cond:
        raise AssertionError("FAILED: " + name)


class Capture(object):
    """Selector oracle that records its arguments and returns a fixed value."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, selector_obj, index, rec1, rec2):
        self.calls.append((selector_obj, index, rec1, rec2))
        return self.result


def test_zero_index_returns_one_without_reading_inputs():
    # The native fast path returns 1 before any load and with no call,
    # so None inputs must be accepted and the oracle must stay unused.
    oracle = Capture(0)
    check("zero index returns 1 with None inputs",
          selector_inversion_wrapper(0, oracle) == 1)
    check("zero index makes no selector call", oracle.calls == [])
    oracle2 = Capture(1)
    check("zero index ignores garbage inputs",
          selector_inversion_wrapper(0, oracle2, link=0xDEAD,
                                     source=(1, 2, 3, 4)) == 1)
    check("zero index ignores garbage inputs without a call",
          oracle2.calls == [])


def test_inversion_both_ways():
    check("selector 0 inverts to 1",
          selector_inversion_wrapper(3, Capture(0), link=0x1000,
                                     source=(0, 8, 0, 8)) == 1)
    check("selector 1 inverts to 0",
          selector_inversion_wrapper(3, Capture(1), link=0x1000,
                                     source=(0, 8, 0, 8)) == 0)


def test_record_construction_and_selector_object():
    oracle = Capture(0)
    selector_inversion_wrapper(5, oracle, link=0x5000,
                               source=(0x1000, 0x2008, 0x3000, 0x4008))
    check("exactly one selector call", len(oracle.calls) == 1)
    obj, index, rec1, rec2 = oracle.calls[0]
    check("selector object is link + 0x40", obj == 0x5040)
    check("selector index is the wrapper index", index == 5)
    check("record 1 is (f20, f28 - 8)", rec1 == (0x1000, 0x2000))
    check("record 2 is (f40, f48 - 8)", rec2 == (0x3000, 0x4000))


def test_wrapping_subtractions_and_object_add():
    oracle = Capture(1)
    result = selector_inversion_wrapper(
        7, oracle, link=MASK64 - 0x1F,
        source=(0xABCD, 3, 0x1234, 0))
    obj, _index, rec1, rec2 = oracle.calls[0]
    check("link + 0x40 wraps to 0x20", obj == 0x20)
    check("f28 = 3 wraps to 2**64 - 5", rec1 == (0xABCD, MASK64 - 4))
    check("f48 = 0 wraps to 2**64 - 8", rec2 == (0x1234, MASK64 - 7))
    check("wrapped case still inverts", result == 0)


def test_signed_index_passed_to_selector():
    oracle = Capture(0)
    selector_inversion_wrapper(0xFFFFFFFF, oracle, link=0x1000,
                               source=(0, 8, 0, 8))
    check("0xFFFFFFFF index reaches selector as -1",
          oracle.calls[0][1] == -1)
    check("0xFFFFFFFF index is nonzero, so it inverts",
          selector_inversion_wrapper(0xFFFFFFFF, Capture(1), link=0x1000,
                                     source=(0, 8, 0, 8)) == 0)


def test_nonzero_index_requires_inputs():
    for kwargs in ({"source": (0, 8, 0, 8)}, {"link": 0x1000}, {}):
        try:
            selector_inversion_wrapper(2, Capture(0), **kwargs)
            check("missing input raises: %r" % (kwargs,), False)
        except ValueError:
            check("missing input raises: %r" % (kwargs,), True)


def test_packet_sanity():
    import json
    root = os.path.join(os.path.dirname(__file__), "..")
    packet = os.path.join(
        root, "research", "work-items",
        "RE-001-selector-inversion-wrapper-115", "records.json")
    records = json.load(open(packet))
    check("packet binds the node #115 digest",
          records["artifact_sha256"]
          == "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    check("packet wrapper window start",
          records["windows"]["wrapper"]["start"] == "0x5ebd130")
    check("packet selector window start",
          records["windows"]["selector"]["start"] == "0x5f6c2a0")
    check("packet wrapper census lists this wrapper's call site",
          "0x5ebd196" in records["census"]["selector"]["direct_calls"])


def main():
    test_zero_index_returns_one_without_reading_inputs()
    test_inversion_both_ways()
    test_record_construction_and_selector_object()
    test_wrapping_subtractions_and_object_add()
    test_signed_index_passed_to_selector()
    test_nonzero_index_requires_inputs()
    test_packet_sanity()
    print("%d model checks pass" % len(CHECKS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
