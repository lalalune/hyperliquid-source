"""Tests for tools/group_sum_getter_115.py (node #115 group-sum
getter 0x5eeb670 with the nested group sum 0x5f6abb0).

Pytest-style test functions with a plain-python ``__main__`` runner
(pytest is not installed in this environment), printing
ALL TESTS PASSED only when every test passes.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import group_sum_getter_115 as m

PACKET = (Path(__file__).resolve().parents[1] / "research"
          / "work-items" / "RE-001-group-sum-getter-115")


def _obj(inline_descs, vec_descs, field70, vec_span=0, addr=0x1000,
         field10_addr=0x2000, field8c0="F8C0"):
    return {
        "addr": addr,
        "field10": {"addr": field10_addr, "field8c0": field8c0},
        "vec_begin": 0x3000,
        "vec_end": 0x3000 + vec_span,
        "field70": field70,
        "inline_descs": inline_descs,
        "vec_descs": vec_descs,
    }


def test_total_zero_returns_zero_without_calling_callee():
    calls = []
    obj = _obj([], [], 0)
    assert m.group_sum(obj, calls.append) == 0
    assert calls == []


def test_single_inline_group_sums_callee_returns():
    calls = []
    obj = _obj([(2, [{"field28": "A"}, {"field28": "B"}])], [], 1)
    assert m.group_sum(obj, lambda *a: 10) == 20
    assert calls == []


def test_callee_receives_exact_arguments():
    seen = []

    def callee(a1, a2, a3, a4, a5):
        seen.append((a1, a2, a3, a4, a5))
        return 1

    obj = _obj([(1, [{"field28": "ITEM"}])], [], 1,
               addr=0x1000, field10_addr=0x2000, field8c0="F8C0")
    assert m.group_sum(obj, callee) == 1
    assert seen == [("F8C0", 0x1000 + 0x1040, 0x2000 + 0x40,
                     "ITEM", 0x1000 + 0x1118)]


def test_zero_count_group_contributes_nothing():
    obj = _obj([(0, []), (1, [{"field28": "X"}])], [], 2)
    assert m.group_sum(obj, lambda *a: 5) == 5


def test_inline_vector_boundary_at_index_eight():
    # 8 inline groups (indices 0..7) plus 1 vector group (index 8):
    # field70 = 8 inline slots, vec span = 1 entry * 16 bytes.
    inline = [(1, [{"field28": i}]) for i in range(8)]
    vec = [(2, [{"field28": "V0"}, {"field28": "V1"}])]
    obj = _obj(inline, vec, 8, vec_span=16)
    assert m.group_sum(obj, lambda *a: 1) == 10


def test_vector_only_group_past_index_eight():
    # total = vec span 2 entries * 16 bytes / 16 + field70 8 = 10,
    # so indices 0..7 read the (empty) inline descriptors and
    # indices 8 and 9 come from vec_descs.
    inline = [(0, []) for _ in range(8)]
    obj = _obj(inline, [(1, [{"field28": "A"}]),
                        (1, [{"field28": "B"}])], 8, vec_span=32)
    assert m.group_sum(obj, lambda *a: 3) == 6


def test_negative_total_is_a_model_guard():
    obj = _obj([], [], -1)
    try:
        m.group_sum(obj, lambda *a: 1)
    except ValueError:
        pass
    else:
        raise AssertionError("negative total must raise, not loop")


def test_getter_null_object_stores_zero_and_returns_one():
    out = [None]
    assert m.getter("ignored-outer", out, None, lambda *a: 9) == 1
    assert out[0] == 0


def test_getter_nonnull_stores_sum_and_returns_one():
    out = [None]
    obj = _obj([(2, [{"field28": "A"}, {"field28": "B"}])], [], 1)
    assert m.getter("ignored-outer", out, obj, lambda *a: 4) == 1
    assert out[0] == 8


def test_getter_ignores_outer():
    out = [None]
    obj = _obj([(1, [{"field28": "A"}])], [], 1)
    assert m.getter(None, out, obj, lambda *a: 7) == 1
    assert out[0] == 7


def test_packet_checks():
    records = json.loads((PACKET / "records.json").read_text())
    assert records["task_id"] == "RE-001"
    assert records["node"] == 115
    assert records["artifact_sha256"] == (
        "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
    starts = {w["start"] for w in records["windows"]}
    assert starts == {"0x5eeb670", "0x5f6abb0"}
    manifest = (PACKET / "MANIFEST.sha256").read_text()
    for name in ("README.md", "records.json", "frames.txt",
                 "relocations.txt", "export_excerpts.py", "census.py",
                 "verify.py", "function_0x5eeb670.txt",
                 "function_0x5f6abb0.txt"):
        assert name in manifest, name


def main():
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for name, fn in tests:
        fn()
        print("PASS %s" % name)
    print("ALL TESTS PASSED (%d tests)" % len(tests))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
