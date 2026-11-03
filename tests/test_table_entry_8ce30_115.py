"""Tests for the node #115 indexed table entry model
(0x5d8ce30).

Target-grounded expectations: the empty-table rule, the
16-byte-stride positional selection, the sole consumer's
argument setup, and the input guards. Run from the
repository root:

    python3 tests/test_table_entry_8ce30_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from table_entry_8ce30_115 import (
    CONSUMER_ROUTINE, CONSUMER_SITE, ENTRY_STRIDE,
    TABLE_BEGIN_OFFSET, TABLE_END_OFFSET, table_entry)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def main():
    shared = ["e0", "e1", "e2"]

    # 1. Empty table: begin is end, so null, whatever the index.
    result = table_entry(
        {"table_begin_0x988": shared, "table_end_0x990": shared}, 2)
    check("empty table returns null", result is None)
    result = table_entry(
        {"table_begin_0x988": None, "table_end_0x990": None}, 0)
    check("both slots null returns null", result is None)

    # 2. Positional selection: index 0, 1 and the last entry.
    result = table_entry(
        {"table_begin_0x988": shared, "table_end_0x990": ["other"]}, 0)
    check("index 0 selects first entry", result == "e0")
    result = table_entry(
        {"table_begin_0x988": shared, "table_end_0x990": ["other"]}, 1)
    check("index 1 selects second entry", result == "e1")
    result = table_entry(
        {"table_begin_0x988": shared, "table_end_0x990": ["other"]}, 2)
    check("index 2 selects last entry", result == "e2")

    # 3. The table is not written: the entry list is unchanged.
    entries = ["a", "b"]
    table_entry(
        {"table_begin_0x988": entries, "table_end_0x990": ["x"]}, 1)
    check("table unchanged after lookup", entries == ["a", "b"])

    # 4. Pinned constants: offsets, stride, consumer site.
    check("table begin offset", TABLE_BEGIN_OFFSET == 0x988)
    check("table end offset", TABLE_END_OFFSET == 0x990)
    check("entry stride", ENTRY_STRIDE == 16)
    check("consumer routine", CONSUMER_ROUTINE == 0x5D52B60)
    check("consumer site", CONSUMER_SITE == 0x5D52B76)

    # 5. Input guards: null owner, null base with a non-equal
    # end, negative and out-of-range indices all raise.
    for owner, index, name in (
            (None, 0, "null owner raises"),
            ({"table_begin_0x988": None,
              "table_end_0x990": ["x"]}, 0, "null base raises"),
            ({"table_begin_0x988": shared,
              "table_end_0x990": ["x"]}, -1, "negative index raises"),
            ({"table_begin_0x988": shared,
              "table_end_0x990": ["x"]}, 3, "out-of-range index raises")):
        try:
            table_entry(owner, index)
            check(name, False)
        except ValueError:
            check(name, True)

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
