"""Tests for the node #94 MemtableIterator refresh handler family.

Runs under pytest when available, and under plain python3 via its
__main__ runner (pytest is not installed on this VM).
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from memtable_iterator_refresh import (  # noqa: E402
    REPORT_FILE,
    REPORT_FORMAT,
    REPORT_LEVEL,
    MemtableIterator,
    known_predicate,
    refresh,
)

PACKET = os.path.join(os.path.dirname(__file__), "..", "research",
                      "work-items", "RE-001-memtable-iterator-refresh-94")


class Recorder:
    def __init__(self):
        self.frees = []
        self.reports = []

    def delete_array(self, ptr):
        self.frees.append(ptr)

    def report(self, level, context, fmt, filename, detail):
        self.reports.append((level, context, fmt, filename, detail))


def make_iterator(variant_ready=True, **kwargs):
    kwargs.setdefault("memtable_first", lambda: "ignored-sentinel")
    kwargs.setdefault("memtable_ready", lambda: variant_ready)
    kwargs.setdefault("memtable_buffer", lambda: "buf-token")
    return MemtableIterator(**kwargs)


def test_full_refresh_code_zero_no_report():
    rec = Recorder()
    it = make_iterator(width=4, detail="old-detail")
    refresh(it, "ba0", lambda b, w, m: (0, 0, None),
            rec.report, rec.delete_array)
    assert (it.code, it.sub, it.detail) == (0, 0, None)
    assert rec.frees == ["old-detail"]
    assert rec.reports == []
    assert it.events[0] == ("first_virtual", 0x48)
    assert ("ready_stored", True) in it.events


def test_refresh_nonzero_code_reports_after_free():
    rec = Recorder()
    it = make_iterator(width=8, detail="old", context="ctx")
    refresh(it, "cf0", lambda b, w, m: (5, 7, "new-detail"),
            rec.report, rec.delete_array)
    assert (it.code, it.sub, it.detail) == (5, 7, "new-detail")
    assert rec.frees == ["old"]
    assert rec.reports == [(REPORT_LEVEL, "ctx", REPORT_FORMAT,
                            REPORT_FILE, "new-detail")]
    # Install precedes the free, and the free precedes the report.
    kinds = [e[0] for e in it.events]
    assert kinds.index("install") < kinds.index("free_old") < kinds.index("report")


def test_width_zero_returns_but_ready_stored():
    rec = Recorder()
    seen = []
    it = make_iterator(width=0, detail="old")
    refresh(it, "e40", lambda b, w, m: seen.append((b, w)) or (1, 0, "x"),
            rec.report, rec.delete_array)
    assert seen == []
    assert rec.frees == [] and rec.reports == []
    assert it.ready is True
    assert ("return_width_zero",) in it.events


def test_known_predicate_not_ready_returns():
    rec = Recorder()
    it = make_iterator(variant_ready=False, width=4)
    refresh(it, "ba0", lambda b, w, m: (1, 0, "x"),
            rec.report, rec.delete_array)
    assert rec.reports == []
    assert ("return_not_ready",) in it.events


def test_known_predicate_already_installed_returns():
    rec = Recorder()
    it = make_iterator(width=4, code=9)
    refresh(it, "fd0", lambda b, w, m: (1, 0, "x"),
            rec.report, rec.delete_array)
    assert rec.reports == []
    assert it.code == 9
    assert ("return_already_installed",) in it.events


def test_known_predicate_rule():
    assert known_predicate(MemtableIterator(ready=True, code=0)) is True
    assert known_predicate(MemtableIterator(ready=False, code=0)) is False
    assert known_predicate(MemtableIterator(ready=True, code=3)) is False


def test_custom_predicate_false_returns():
    rec = Recorder()
    it = make_iterator(width=4, predicate_kind="custom",
                       predicate_fn=lambda: False)
    refresh(it, "ba0", lambda b, w, m: (1, 0, "x"),
            rec.report, rec.delete_array)
    assert ("return_predicate_false",) in it.events
    assert rec.reports == []


def test_custom_predicate_true_skips_inline_checks():
    # Predicate path proceeds even with ready False and code nonzero:
    # the binary skips the inline ready/clear checks on this path.
    rec = Recorder()
    it = make_iterator(variant_ready=False, width=4, code=9,
                       predicate_kind="custom", predicate_fn=lambda: True)
    refresh(it, "ba0", lambda b, w, m: (0, 0, None),
            rec.report, rec.delete_array)
    assert (it.code, it.detail) == (0, None)
    assert ("predicate", True) in it.events


def test_84d0_reads_stored_ready_and_skips_virtuals():
    rec = Recorder()
    calls = []
    it = MemtableIterator(ready=True, width=2, detail="old",
                          memtable_first=lambda: calls.append("first"),
                          memtable_ready=lambda: calls.append("ready") or False,
                          memtable_buffer=lambda: "buf")
    refresh(it, "84d0", lambda b, w, m: (0, 0, None),
            rec.report, rec.delete_array)
    assert calls == []
    assert rec.frees == ["old"]
    assert it.ready is True


def test_84d0_stored_not_ready_returns():
    rec = Recorder()
    it = MemtableIterator(ready=False, width=2,
                          memtable_buffer=lambda: "buf")
    refresh(it, "84d0", lambda b, w, m: (1, 0, "x"),
            rec.report, rec.delete_array)
    assert rec.reports == []
    assert ("return_not_ready",) in it.events


def test_first_virtual_result_ignored():
    rec = Recorder()
    it = make_iterator(width=4)
    refresh(it, "ba0", lambda b, w, m: (0, 0, None),
            rec.report, rec.delete_array)
    assert ("first_virtual", 0x48) in it.events
    assert it.code == 0


def test_perf_counter_only_when_level_above_one():
    for level, present, expected in ((0, True, 0), (1, True, 0),
                                     (2, True, 1), (2, False, 1)):
        rec = Recorder()
        it = make_iterator(width=4, perf_slot_present=present,
                           perf_level=level, perf_counters={})
        refresh(it, "e40", lambda b, w, m: (0, 0, None),
                rec.report, rec.delete_array)
        assert it.perf_counters.get(0x150, 0) == expected
        if level > 1:
            assert ("perf_start",) in it.events
        else:
            assert ("perf_start",) not in it.events


def test_perf_counters_differ_per_variant():
    for variant, key in (("e40", 0x150), ("fd0", 0x148)):
        rec = Recorder()
        it = make_iterator(width=4, perf_slot_present=True, perf_level=3,
                           perf_counters={})
        refresh(it, variant, lambda b, w, m: (0, 0, None),
                rec.report, rec.delete_array)
        assert it.perf_counters == {key: 1}


def test_aliasing_quirk_install_before_free():
    # Observed binary order: install, then free the old pointer, even
    # when the new detail is the same object as the old one.
    rec = Recorder()
    it = make_iterator(width=4, detail="same-token")
    refresh(it, "ba0", lambda b, w, m: (3, 0, "same-token"),
            rec.report, rec.delete_array)
    assert it.detail == "same-token"
    assert rec.frees == ["same-token"]
    assert rec.reports != []


def test_no_old_detail_no_free():
    rec = Recorder()
    it = make_iterator(width=4, detail=None)
    refresh(it, "cf0", lambda b, w, m: (0, 0, "fresh"),
            rec.report, rec.delete_array)
    assert rec.frees == []
    assert it.detail == "fresh"


def test_code_zero_with_detail_no_report():
    rec = Recorder()
    it = make_iterator(width=4, detail="old")
    refresh(it, "ba0", lambda b, w, m: (0, 0, "detail-kept"),
            rec.report, rec.delete_array)
    assert it.detail == "detail-kept"
    assert rec.reports == []


def test_all_variants_share_core_events():
    core = ["buffer", "reader", "install"]
    for variant in ("ba0", "cf0", "e40", "fd0", "84d0"):
        rec = Recorder()
        it = make_iterator(width=4, detail="old", ready=True,
                           perf_slot_present=False, perf_level=0)
        refresh(it, variant, lambda b, w, m: (0, 0, None),
                rec.report, rec.delete_array)
        kinds = [e[0] for e in it.events]
        for step in core:
            assert step in kinds


def test_reader_receives_width_and_mode_zero():
    seen = []
    rec = Recorder()
    it = make_iterator(width=8)
    refresh(it, "ba0", lambda b, w, m: seen.append((b, w, m)) or (0, 0, None),
            rec.report, rec.delete_array)
    assert seen == [("buf-token", 8, 0)]


def test_packet_records_parse_and_cover_windows():
    with open(os.path.join(PACKET, "records.json")) as f:
        records = json.load(f)
    assert records["artifact"]["sha256"].startswith("3b7179cd")
    assert len(records["windows"]) == 5
    assert records["predicate"]["rule"].startswith("returns true exactly")
    assert len(records["reader"]["call_sites"]) == 8
    assert sum(1 for s in records["reader"]["call_sites"]
               if s["in_scope"]) == 5
    for window in records["windows"]:
        name = "window-%s.txt" % window["address"][2:]
        assert os.path.exists(os.path.join(PACKET, name)), name


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


if __name__ == "__main__":
    passed = 0
    for test in TESTS:
        test()
        passed += 1
        print("PASS %s" % test.__name__)
    print("%d tests pass" % passed)
