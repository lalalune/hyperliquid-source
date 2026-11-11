"""Tests for tools/member_tree_teardown_573f0_115.py.

Plain test_* functions so they run under pytest and by direct
invocation (pytest is not installed on this VM).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from member_tree_teardown_573f0_115 import teardown


def _node(next_id=None, child_id=None, string=("s", None)):
    return {"next": next_id, "child": child_id, "string": string}


def test_null_root_destroys_nothing():
    assert teardown(None, {}) == []


def test_single_short_string_node():
    nodes = {"a": _node(string=("hi", None))}
    assert teardown("a", nodes) == [
        ("member_call", "a", 0x5D35C30),
        ("dispose_string", "a", "manual", "short"),
        ("free_node", "a", 0x58),
    ]


def test_single_heap_string_node():
    nodes = {"a": _node(string=("hello", 0x20))}
    ops = teardown("a", nodes)
    assert ops[1] == ("dispose_string", "a", "manual", "sized", 0x21)
    assert ops[2] == ("free_node", "a", 0x58)


def test_member_call_precedes_string_precedes_free():
    nodes = {"a": _node(child_id="b"), "b": _node()}
    ops = teardown("a", nodes)
    kinds = [op[0] for op in ops]
    assert kinds == ["member_call", "dispose_string", "free_node",
                     "member_call", "dispose_string", "free_node"]
    assert ops[0][1] == "b" and ops[3][1] == "a"


def test_post_order_siblings_and_children():
    # root a: child b (with next sibling c), next sibling d.
    # Order: b subtree, a, then d (d has no child).
    nodes = {
        "a": _node(next_id="d", child_id="b"),
        "b": _node(next_id="c"),
        "c": _node(),
        "d": _node(),
    }
    freed = [op[1] for op in teardown("a", nodes) if op[0] == "free_node"]
    assert freed == ["b", "c", "a", "d"]


def test_depth_nine_frame_reset():
    # A 10-deep child chain: depths 0..9. Post-order frees deepest
    # first. Depth 9 is a fresh recursion root, so it uses the manual
    # idiom again, while depths 5..8 use _M_dispose.
    ids = [f"n{i}" for i in range(10)]
    nodes = {}
    for i, nid in enumerate(ids):
        nodes[nid] = _node(child_id=ids[i + 1] if i + 1 < 10 else None)
    ops = teardown(ids[0], nodes)
    disposes = {op[1]: op[2] for op in ops if op[0] == "dispose_string"}
    assert disposes["n9"] == "manual"
    for i in (5, 6, 7, 8):
        assert disposes[f"n{i}"] == "m_dispose"
    for i in (0, 1, 2, 3, 4):
        assert disposes[f"n{i}"] == "manual"
    freed = [op[1] for op in ops if op[0] == "free_node"]
    assert freed == list(reversed(ids))


def test_cyclic_graph_raises():
    nodes = {"a": _node(child_id="b"), "b": _node(child_id="a")}
    try:
        teardown("a", nodes)
    except ValueError:
        return
    raise AssertionError("cyclic graph did not raise")
