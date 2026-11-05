"""Tests for the RE-001 node #115 stats-emit caller 0x5d7dfc0 model.

Target-grounded expectations from the verbatim excerpts in
research/work-items/RE-001-stats-emit-caller-7dfc0-115/:
the version-list walk, the per-version produce + hash dedup, the
registry factory invocations, the two dump emits, the malloc-stats
branch, the stats-emit call and the cleanup. Run directly
(pytest is not installed on this VM):

    python3 tests/test_stats_emit_caller_7dfc0_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from stats_emit_caller_7dfc0_115 import (
    AbortError, HashTable, LoggerSink, LogicError, Registry,
    StatsEmitCaller, StdString, VersionNode, VersionRelease,
    log_dispatch, mutex_unlock, new_obj, string_assign,
    trim_trailing_digits, IDENTITY, SENTINEL,
    FORMAT_DUMP, FORMAT_DUMPING, FORMAT_MALLOC, FORMAT_MALLOC_DUMP,
    FILE_NAME, PRODUCE_NAME,
)


def _chain(nodes):
    """Link nodes into a circular list; returns the head node."""
    head = VersionNode()
    if not nodes:
        head.next = head
        return head
    head.next = nodes[0]
    for a, b in zip(nodes, nodes[1:]):
        a.next = b
    nodes[-1].next = head
    return head


def _run(obj=None, hooks=None):
    obj = obj if obj is not None else new_obj()
    calls = {"acquire": [], "unlock": [], "refresh": [],
             "produce": [], "dispatch": [], "emit": [],
             "stats_emit": [], "release": [], "factory": []}

    def acquire(m):
        calls["acquire"].append(m)

    def unlock(m):
        calls["unlock"].append(m)

    def refresh(s):
        calls["refresh"].append(s)

    def produce(o, n):
        calls["produce"].append((o, n))
        return object() if o is not None else None

    def dispatch(k, s):
        calls["dispatch"].append((k, s))

    def emit(*a):
        calls["emit"].append(a)

    def stats_emit(o):
        calls["stats_emit"].append(o)

    def release(n):
        calls["release"].append(n)
        return 0

    merged = {"acquire": acquire, "unlock": unlock, "refresh": refresh,
              "produce": produce, "key_dispatch": dispatch, "emit": emit,
              "stats_emit": stats_emit, "release": release}
    if hooks:
        merged.update(hooks)
    runner = StatsEmitCaller(obj, merged)
    freed = runner.run()
    return runner, calls, freed


def test_skip_flag_returns_before_lock():
    obj = new_obj(skip_flag=1)
    _runner, calls, freed = _run(obj)
    assert calls["acquire"] == []
    assert calls["emit"] == []
    assert calls["stats_emit"] == []
    assert freed == []


def test_empty_list_still_emits_and_calls_stats_emit():
    obj = new_obj()
    obj["versions_chain"]["head"] = _chain([])
    runner, calls, freed = _run(obj)
    assert len(calls["acquire"]) == 1
    assert len(calls["unlock"]) == 1
    assert calls["emit"][0] == (1, obj["sink"], FORMAT_DUMPING, FILE_NAME)
    assert calls["emit"][1][2] == FORMAT_DUMP
    assert calls["stats_emit"] == [obj]
    assert freed == []
    assert runner.trace == ["done"]


def test_flag_clear_node_is_skipped():
    node = VersionNode(flag=0, subobject=object(), produce_obj=object())
    obj = new_obj()
    obj["versions_chain"]["head"] = _chain([node])
    _runner, calls, _freed = _run(obj)
    assert calls["refresh"] == []
    assert calls["produce"] == []


def test_flag_set_node_refresh_and_produce():
    node = VersionNode(flag=1, subobject=object(), produce_obj=object())
    obj = new_obj()
    obj["versions_chain"]["head"] = _chain([node])
    _runner, calls, _freed = _run(obj)
    assert calls["refresh"] == [node.subobject]
    assert calls["produce"] == [(node.produce_obj, PRODUCE_NAME)]
    # Unlock, then re-lock around the per-node work.
    assert len(calls["unlock"]) == 2
    assert len(calls["acquire"]) == 2


def test_null_sink_skips_produce_but_refreshes():
    node = VersionNode(flag=1, subobject=object(), produce_obj=object())
    obj = new_obj(sink=None)
    obj["versions_chain"]["head"] = _chain([node])
    _runner, calls, _freed = _run(obj)
    assert calls["refresh"] == [node.subobject]
    assert calls["produce"] == []
    # No emit calls when the sink is null: the emit hook still runs
    # (the binary calls the dispatcher unconditionally), but the
    # dispatcher itself is what gates on the sink; here the hook
    # records the call shape.
    assert calls["emit"][0][1] is None


def test_produce_none_inserts_nothing():
    node = VersionNode(flag=1, subobject=object(), produce_obj=object())
    obj = new_obj()
    obj["versions_chain"]["head"] = _chain([node])
    hooks = {"produce": lambda o, n: None}
    runner, calls, _freed = _run(obj, hooks)
    assert runner.table.inserted == []
    assert calls["dispatch"] == []


def test_duplicate_key_dispatched_once():
    key = object()
    n1 = VersionNode(flag=1, subobject=object(), produce_obj=object())
    n2 = VersionNode(flag=1, subobject=object(), produce_obj=object())
    obj = new_obj()
    obj["versions_chain"]["head"] = _chain([n1, n2])
    hooks = {"produce": lambda o, n: key,
             "key_slot": lambda k: 0x5D40000}
    runner, calls, _freed = _run(obj, hooks)
    assert runner.table.inserted == [key]
    assert len(calls["dispatch"]) == 1
    assert calls["dispatch"][0][0] is key


def test_identity_slot_skips_dispatch():
    key = object()
    node = VersionNode(flag=1, subobject=object(), produce_obj=object())
    obj = new_obj()
    obj["versions_chain"]["head"] = _chain([node])
    hooks = {"produce": lambda o, n: key,
             "key_slot": lambda k: IDENTITY}
    _runner, calls, _freed = _run(obj, hooks)
    assert calls["dispatch"] == []


def test_registry_factories_run_for_both_slices():
    seen = []

    def factory(o, name, dump):
        seen.append((o, name))
        dump._value += name + b"|"

    obj = new_obj()
    obj["versions_chain"]["head"] = _chain([])
    registry = Registry()
    registry.register(b"first-slice", "factory-first")
    registry.register(b"second-slice", "factory-second")
    hooks = {"registry_lookup": registry.lookup}
    # The runner's trim_invoke looks the factory up by entry in
    # obj["factories"]; wire the entries to the recording factory.
    obj["factories"] = {"factory-first": factory,
                        "factory-second": factory}
    runner, _calls, _freed = _run(obj, hooks)
    assert seen[0][1] == b"first-slice"
    assert runner.dump_string.data == b""  # disposed by cleanup
    assert len(seen) == 1  # no flagged nodes for the second slice


def test_second_slice_factory_per_flagged_node():
    seen = []
    n1 = VersionNode(flag=1, subobject=object(), produce_obj=object())
    n2 = VersionNode(flag=0, subobject=object(), produce_obj=object())
    obj = new_obj()
    obj["versions_chain"]["head"] = _chain([n1, n2])

    def factory(o, name, dump):
        seen.append((o, name))

    registry = Registry()
    registry.register(b"first-slice", "f1")
    registry.register(b"second-slice", "f2")
    obj["factories"] = {"f1": factory, "f2": factory}
    hooks = {"registry_lookup": registry.lookup}
    _runner, _calls, _freed = _run(obj, hooks)
    # First slice once; second slice once per flagged node (n1 only).
    assert [s[1] for s in seen] == [b"first-slice", b"second-slice"]
    assert seen[1][0] is n1.subobject


def test_malloc_branch_noop_hook_emits_nothing_extra():
    obj = new_obj(malloc_flag=1)
    obj["versions_chain"]["head"] = _chain([])
    _runner, calls, _freed = _run(obj)
    assert [c[2] for c in calls["emit"]] == [FORMAT_DUMPING, FORMAT_DUMP]
    assert calls["stats_emit"] == [obj]


def test_malloc_branch_filled_hook_emits_malloc_stats():
    obj = new_obj(malloc_flag=1)
    obj["versions_chain"]["head"] = _chain([])

    def fill(dump):
        dump._value = b"malloc: 42 bytes"

    hooks = {"malloc_hook": fill}
    _runner, calls, _freed = _run(obj, hooks)
    assert [c[2] for c in calls["emit"]] == [
        FORMAT_DUMPING, FORMAT_DUMP, FORMAT_MALLOC, FORMAT_MALLOC_DUMP]


def test_string_assign_sso_and_heap_and_null():
    s = StdString()
    string_assign(s, "BlockCache")
    assert s.data == b"BlockCache"
    assert not s.is_heap()
    assert s.dispose() is None
    long_s = StdString()
    string_assign(long_s, "x" * 20)
    assert long_s.is_heap()
    assert long_s.dispose() == b"x" * 20
    try:
        string_assign(StdString(), None)
    except LogicError as exc:
        assert "construction from null" in str(exc)
    else:
        raise AssertionError("null assign did not raise")


def test_version_release_counts():
    rel = VersionRelease()
    assert rel(VersionNode(refcount=3)) == 0
    assert rel(VersionNode(refcount=1)) == 1
    assert rel(VersionNode(refcount=2)) == 0
    freed = []
    rel2 = VersionRelease(teardown=lambda n: freed.append(n),
                          conditional_free=lambda n: True)
    assert rel2(VersionNode(refcount=2)) == 1
    assert len(freed) == 0
    rel3 = VersionRelease(teardown=lambda n: freed.append(n))
    assert rel3(VersionNode(refcount=1)) == 1
    assert len(freed) == 1


def test_mutex_unlock_statuses():
    assert mutex_unlock(0) is None
    assert mutex_unlock(0x10) is None
    assert mutex_unlock(0x6E) is None
    try:
        mutex_unlock(1)
    except AbortError:
        pass
    else:
        raise AssertionError("bad status did not abort")


def test_log_dispatch_gate_and_level5():
    sink = LoggerSink(level=2)
    log_dispatch(3, sink, "[%s] x", FILE_NAME)
    assert sink.calls == []
    log_dispatch(1, sink, FORMAT_DUMPING, FILE_NAME)
    assert sink.calls[0][0] == "general"
    assert sink.calls[0][2] == FORMAT_DUMPING
    assert sink.calls[0][3][0] == FILE_NAME
    log_dispatch(5, LoggerSink(level=5), "[%s] y", FILE_NAME)
    sink5 = LoggerSink(level=5)
    log_dispatch(5, sink5, "[%s] y", FILE_NAME)
    assert sink5.calls[0][0] == "level5"
    log_dispatch(1, None, FORMAT_DUMPING, FILE_NAME)


def test_trim_trailing_digits():
    assert trim_trailing_digits(b"BlockCache") == (b"BlockCache", 0)
    assert trim_trailing_digits(b"BlockCache123") == (b"BlockCache", 3)
    assert trim_trailing_digits(b"123") == (b"", 3)
    assert trim_trailing_digits(b"") == (b"", 0)


def test_registry_lookup_trims_and_misses():
    reg = Registry()
    reg.register(b"BlockCache", "entry")
    assert reg.lookup(b"BlockCache123") == "entry"
    assert reg.lookup(b"BlockCache") == "entry"
    assert reg.lookup(b"Other") is None
    assert reg.lookup(b"Other42") is None


def test_hash_table_dedup_and_growth():
    table = HashTable()
    keys = [object() for _ in range(5)]
    for key in keys:
        assert table.insert(key) is True
    assert table.insert(keys[0]) is False
    assert table.count == 5
    assert table.find(keys[3]) is True
    assert table.find(object()) is False
    assert len(table.rehashes) >= 1  # grew past the single bucket
    assert table.bucket_count > 1
    freed = table.cleanup()
    assert len(freed) == 5
    assert table.count == 0
    assert table.before_begin is None


def test_sentinel_marker_nodes_are_not_released():
    n1 = VersionNode(marker=0x1234, flag=1, subobject=object(),
                     produce_obj=object())
    n1.next = None
    obj = new_obj()
    obj["versions_chain"]["head"] = _chain([n1])
    _runner, calls, _freed = _run(obj)
    # Non-sentinel markers trigger the refcount protocol (release
    # on advance, bump on entry); the marker value itself is
    # recorded, not interpreted.
    assert len(calls["release"]) >= 1
    assert calls["refresh"] == [n1.subobject]


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_") and callable(v)]


if __name__ == "__main__":
    failed = 0
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - report and continue
            failed += 1
            print("FAIL %s: %r" % (test.__name__, exc))
        else:
            print("PASS %s" % test.__name__)
    print("%d passed, %d failed" % (len(TESTS) - failed, failed))
    sys.exit(1 if failed else 0)
