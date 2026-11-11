"""Tests for tools/record_pushback_115.py (RE-001).

Run directly (pytest is not installed on this VM):
    python3 tests/test_record_pushback_115.py
Prints "all N checks passed" on success, else raises.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from record_pushback_115 import (  # noqa: E402
    ELEMENT_SIZE, LengthError, MAX_SIZE, Record, RecordVector,
    empty_key_record, factory_options_record, key_from_chunks,
    new_capacity, string_storage, table_init_record,
)

CHECKS = [0]


def check(cond, label):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("check failed: %s" % label)


def main():
    # Element layout: 48 bytes; string 0x20, a +0x20, b +0x28.
    check(ELEMENT_SIZE == 48, "element size is 0x30")
    rec = Record("BlockTableOptions", 0x100020, 0x6507540)
    check(rec.as_tuple() == ("BlockTableOptions", 0x100020, 0x6507540),
          "record tuple")
    check(rec.storage == "heap", "17-char key is heap-backed")

    # SSO / heap split at the 15-char boundary.
    check(string_storage("") == ("sso", ""), "empty key is SSO")
    check(string_storage("a") == ("sso", "a"), "1-char key is SSO")
    check(string_storage("x" * 15) == ("sso", "x" * 15),
          "15-char key is SSO")
    check(string_storage("x" * 16) == ("heap", "x" * 16),
          "16-char key is heap-backed")
    check(string_storage("BlockTableOptions") == ("heap", "BlockTableOptions"),
          "BlockTableOptions is heap-backed")
    check(string_storage("SkipListFactoryOptions") ==
          ("heap", "SkipListFactoryOptions"),
          "SkipListFactoryOptions is heap-backed")

    # Growth rule: empty -> 1, else min(2*size, MAX_SIZE).
    check(new_capacity(0) == 1, "empty vector grows to 1")
    check(new_capacity(1) == 2, "size 1 grows to 2")
    check(new_capacity(2) == 4, "size 2 grows to 4")
    check(new_capacity(3) == 6, "size 3 grows to 6")
    check(new_capacity(100) == 200, "size 100 grows to 200")
    check(new_capacity(MAX_SIZE - 1) == MAX_SIZE,
          "doubling caps at MAX_SIZE")
    try:
        new_capacity(MAX_SIZE)
        check(False, "MAX_SIZE must raise LengthError")
    except LengthError as exc:
        check(str(exc) == "vector::_M_realloc_insert",
              "length_error message names _M_realloc_insert")
    check(MAX_SIZE == 0x2AAAAAAAAAAAAAA, "MAX_SIZE constant")
    check(MAX_SIZE == (2 ** 63 - 1) // 48, "MAX_SIZE is (2^63-1)//48")

    # Fast path vs growth path, capacity doubling, order kept.
    vec = RecordVector()
    check(len(vec) == 0 and vec.capacity == 0, "fresh vector is empty")
    check(vec.push_back("a", 0x1000, 0x2000) == "growth",
          "first append takes the growth path (cap 0)")
    check(len(vec) == 1 and vec.capacity == 1, "cap 1 after first append")
    check(vec.items[0].as_tuple() == ("a", 0x1000, 0x2000),
          "first record stored")
    check(vec.push_back("bb", 0x1001, 0x2001) == "growth",
          "second append grows cap 1 -> 2")
    check(vec.capacity == 2, "cap 2 after second append")
    check(vec.push_back("ccc", 0x1002, 0x2002) == "growth",
          "third append grows cap 2 -> 4")
    check(vec.capacity == 4, "cap 4 after third append")
    check(vec.push_back("dddd", 0x1003, 0x2003) == "fast",
          "fourth append is the fast path")
    check(vec.push_back("eeeee", 0x1004, 0x2004) == "growth",
          "fifth append grows cap 4 -> 8")
    check(vec.capacity == 8, "cap 8 after fifth append")
    check([r.key for r in vec.items] ==
          ["a", "bb", "ccc", "dddd", "eeeee"], "order preserved by moves")
    check([r.as_tuple() for r in vec.items] ==
          [("a", 0x1000, 0x2000), ("bb", 0x1001, 0x2001),
           ("ccc", 0x1002, 0x2002), ("dddd", 0x1003, 0x2003),
           ("eeeee", 0x1004, 0x2004)], "records intact after growth")

    # Long keys survive growth (heap copy, not a dangling alias).
    vec2 = RecordVector()
    vec2.push_back("SkipListFactoryOptions", 0x300020, 0x6505C40)
    vec2.push_back("BlockTableOptions", 0x300020, 0x6507540)
    vec2.push_back("", 0x300020, 0x6504B80)
    check([r.key for r in vec2.items] ==
          ["SkipListFactoryOptions", "BlockTableOptions", ""],
          "long keys survive the growth moves")
    check(all(r.storage == ("heap" if len(r.key) > 15 else "sso")
              for r in vec2.items), "storage classes survive growth")

    # The 0x6064440 key construction: 16-byte chunk + 8-byte chunk
    # stored at +14, overwriting the tail, final size 22.
    key = key_from_chunks(b"SkipListFactoryO", b"yOptions", 14, 22)
    check(key == "SkipListFactoryOptions",
          "overlapping chunks build SkipListFactoryOptions")
    check(len(key) == 22, "SkipListFactoryOptions is 22 chars")

    # The three pinned registration call sites.
    owner = 0x100000
    t = table_init_record(owner)
    check(t.as_tuple() == ("BlockTableOptions", owner + 0x20, 0x6507540),
          "table_init record")
    check(t.storage == "heap", "table_init key is heap-backed")
    f = factory_options_record(owner)
    check(f.as_tuple() ==
          ("SkipListFactoryOptions", owner + 0x20, 0x6505C40),
          "0x6064440 record")
    e = empty_key_record(owner)
    check(e.as_tuple() == ("", owner + 0x20, 0x6504B80),
          "0x5fd0090 record")
    check(e.storage == "sso", "empty key is SSO")

    # End to end: the table_init sequence on a fresh object.
    vec3 = RecordVector()
    check(vec3.push_back(*t.as_tuple()) == "growth",
          "table_init append takes the growth path on a fresh vector")
    check(len(vec3) == 1 and vec3.capacity == 1,
          "one record, cap 1 after the table_init append")
    check(vec3.items[0] == t, "table_init record is the stored record")

    # The 0x6064440 + 0x5fd0090 objects each start with an empty
    # vector triple and append exactly one record.
    for make in (factory_options_record, empty_key_record):
        v = RecordVector()
        r = make(owner)
        check(v.push_back(*r.as_tuple()) == "growth",
              "fresh-object append takes the growth path")
        check(len(v) == 1, "exactly one record appended")

    print("all %d checks passed" % CHECKS[0])


if __name__ == "__main__":
    sys.exit(main())
