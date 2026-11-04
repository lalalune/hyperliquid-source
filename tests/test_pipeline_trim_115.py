"""Tests for the node #115 pipeline prologue + trim (tools/pipeline_trim_115.py).

Run directly: python3 tests/test_pipeline_trim_115.py
(pytest is not installed on this VM; the file runs its checks under
plain python3 via the __main__ runner below, as in the recent RE-001
packets.)
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
from pipeline_trim_115 import (  # noqa: E402
    PipelineTrimError, pipeline_prologue, trim_trailing_empty_groups)

E = (0, 0)  # empty group: begin == end


def check(name, got, want):
    assert got == want, "%s: got %r, want %r" % (name, got, want)
    print("ok:", name)


def expect_error(name, fn):
    try:
        fn()
    except PipelineTrimError:
        print("ok:", name)
        return
    raise AssertionError("%s: expected PipelineTrimError" % name)


def test_trim():
    check("last non-empty keeps count",
          trim_trailing_empty_groups(3, [(0, 8), (8, 16), (16, 24)]), 3)
    check("one trailing empty drops one",
          trim_trailing_empty_groups(3, [(0, 8), (8, 16), E]), 2)
    check("three trailing empties drop three",
          trim_trailing_empty_groups(4, [(0, 8), E, E, E]), 1)
    check("all empty trims to zero",
          trim_trailing_empty_groups(3, [E, E, E]), 0)
    check("single empty trims to zero",
          trim_trailing_empty_groups(1, [E]), 0)
    check("zero count returns zero",
          trim_trailing_empty_groups(0, []), 0)
    check("negative count stored as-is",
          trim_trailing_empty_groups(-2, []), -2)
    check("begin past end is not empty",
          trim_trailing_empty_groups(2, [(0, 8), (16, 8)]), 2)
    check("empty middle group does not stop the scan",
          trim_trailing_empty_groups(3, [(0, 8), E, (16, 24)]), 3)
    expect_error("short list guarded",
                 lambda: trim_trailing_empty_groups(3, [(0, 8)]))
    expect_error("count out of s32 range guarded",
                 lambda: trim_trailing_empty_groups(1 << 31, []))


def test_pipeline():
    groups = [(0, 8), (8, 16), E]
    trimmed, seq, final = pipeline_prologue(3, groups, 0, steps=[])
    check("pipeline trimmed count", trimmed, 2)
    check("pipeline call order", [s[0] for s in seq],
          ["0x5f6b660", "trim", "0x5f79580", "0x5f870a0", "0x5f9c7b0",
           "0x5f801f0", "0x5f6bc90", "0x5f6d700", "tail 0x5f880b0"])
    check("0x5f9c7b0 receives trimmed count",
          [s for s in seq if s[0] == "0x5f9c7b0"], [("0x5f9c7b0", 2)])
    check("flag clear takes the 0x5f6d700 path", final, "via-0x5f6d700")
    trimmed, seq, final = pipeline_prologue(3, groups, 1, steps=[])
    check("flag set skips 0x5f6d700", "0x5f6d700" in [s[0] for s in seq],
          False)
    check("flag set tails direct", final, "tail-direct")
    check("flag set still trims", trimmed, 2)
    trimmed, seq, final = pipeline_prologue(2, [E, E], 0, steps=[])
    check("all-empty pipeline trims to zero", trimmed, 0)
    check("all-empty 0x5f9c7b0 arg is zero",
          [s for s in seq if s[0] == "0x5f9c7b0"], [("0x5f9c7b0", 0)])


def test_packet():
    here = os.path.join(os.path.dirname(__file__), "..",
                         "research", "work-items",
                         "RE-001-pipeline-trim-115")
    records = json.load(open(os.path.join(here, "records.json")))
    check("packet census trim calls",
          records["census"]["trim"]["direct_calls"], ["0x5f884c9"])
    check("packet census pipeline tails",
          records["census"]["pipeline"]["tail_jumps"], ["0x5f8857c"])
    check("packet windows", sorted(records["windows"]),
          ["pipeline", "trim"])


def main():
    test_trim()
    test_pipeline()
    test_packet()
    print("ALL MODEL TESTS PASSED")


if __name__ == "__main__":
    main()
