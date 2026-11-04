"""Tests for tools/element_visit_reset_115.py."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from element_visit_reset_115 import (  # noqa: E402
    element_visit_reset, site1_call_arg, site2_call_arg)

CHECKS = []


def check(name, condition):
    CHECKS.append(name)
    assert condition, name


def main():
    # Empty range: no visit, field 0 zeroed, end untouched (= begin).
    seen = []
    obj = {0x00: 7, 0x08: 0x1000, 0x10: 0x1000}
    assert element_visit_reset(obj, seen.append) == []
    check("empty no visits", seen == [])
    check("empty zeroes field 0", obj[0x00] == 0)
    check("empty end unchanged", obj[0x10] == 0x1000)
    check("begin untouched", obj[0x08] == 0x1000)

    # Single element, return discarded.
    seen = []
    obj = {0x00: 3, 0x08: 0x2000, 0x10: 0x2180}
    visited = element_visit_reset(obj, lambda p: seen.append(p) or 99)
    check("single visit", visited == [0x2000] and seen == [0x2000])
    check("single resets end", obj[0x10] == 0x2000 and obj[0x00] == 0)

    # Three elements in increasing order, stride 0x180.
    seen = []
    obj = {0x00: 1, 0x08: 0x3000, 0x10: 0x3480}
    visited = element_visit_reset(obj, seen.append)
    check("three in order", visited == [0x3000, 0x3180, 0x3300])
    check("three resets", obj[0x10] == 0x3000 and obj[0x08] == 0x3000)

    # Field 0 is zeroed even before the first visit is observed.
    order = []
    def visit(p):
        order.append(("visit", obj[0x00]))
    obj = {0x00: 5, 0x08: 0x4000, 0x10: 0x4180}
    element_visit_reset(obj, visit)
    check("field 0 zero before visit", order == [("visit", 0)])

    # Guards.
    for missing in (0x00, 0x08, 0x10):
        obj = {0x00: 0, 0x08: 0x1000, 0x10: 0x1000}
        del obj[missing]
        try:
            element_visit_reset(obj, lambda p: None)
            raise AssertionError("missing field not raised")
        except ValueError:
            pass
    check("missing-field guards", True)
    for begin, end in ((0x1000, 0x1080), (0x2000, 0x1000), (0x1000, 0x1001)):
        obj = {0x00: 0, 0x08: begin, 0x10: end}
        try:
            element_visit_reset(obj, lambda p: None)
            raise AssertionError("bad range not raised")
        except ValueError:
            pass
    check("unaligned/inverted raises", True)

    # Site helpers.
    check("site1 zero pointer", site1_call_arg(0) is None)
    check("site1 shifts by 0x18", site1_call_arg(0x5000) == 0x5018)
    check("site2 passes object", site2_call_arg(0x6000) == 0x6000)

    # Packet checks: semantic records only, no per-instruction list.
    import json
    packet = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-element-visit-reset-115"
    records = json.loads((packet / "records.json").read_text())
    check("records routine", records["routine"]["address"] == "0x5f6eac0")
    check("records sites", [s["site"] for s in records["call_sites"]] == ["0x5f76388", "0x5fa1796"])
    check("records no instruction list", "instructions" not in records and "mnemonics" not in records)
    print("%d checks passed" % len(CHECKS))


if __name__ == "__main__":
    main()
