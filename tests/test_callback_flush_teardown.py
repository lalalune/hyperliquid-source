"""Tests for tools/callback_flush_teardown.py (node #94 0x5165b80).

pytest-style file; pytest is not installed on this VM, so the __main__
runner below runs the same test_* functions under plain python3.
"""

import os
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from callback_flush_teardown import (  # noqa: E402
    CallbackNode, Record, StringNode, TreeNode, flush_and_destroy,
)


def make_registry(calls):
    """Registry mapping small integer fn keys to recording callables."""
    return {k: (lambda *args, k=k: calls.append((k,) + args))
            for k in range(1, 64)}


def test_null_inner_noop():
    calls = []
    events = flush_and_destroy(None, make_registry(calls))
    assert events == []
    assert calls == []


def test_clean_path_order():
    calls = []
    reg = make_registry(calls)
    rec = Record(
        dirty=False,
        array=[(9, 2)],
        array_capacity_pairs=4,
        callback_fn=3, callback_arg0=10, callback_arg1=20,
        callback_tail=[CallbackNode(4, 30, 40)],
        string_nodes=[StringNode(inline=True),
                      StringNode(inline=False, capacity=7)],
        tree_nodes=[TreeNode()],
        vec_a=16, vec_b=32, vec_c=48,
    )
    events = flush_and_destroy(rec, reg)
    assert rec.deleted
    # Clean path: no array callbacks; array freed BEFORE the list drain.
    assert ("array_callback", 9, 2) not in events
    assert events.index(("array_freed", 64)) < events.index(
        ("list_callback", 10, 20, 3))
    assert events == [
        ("array_freed", 64),
        ("list_callback", 10, 20, 3),
        ("list_callback", 30, 40, 4),
        ("list_node_freed", 0x20),
        ("string_node_freed", 0x30),
        ("string_heap_freed", 8),
        ("string_node_freed", 0x30),
        ("tree_node_freed", 0x28),
        ("tree_list_node_freed", 0x28),
        ("vector_freed", "vec_c", 48),
        ("vector_freed", "vec_b", 32),
        ("vector_freed", "vec_a", 16),
        ("inner_deleted", 0xE8),
    ]
    assert calls == [(3, 10, 20), (4, 30, 40)]


def test_dirty_path_sorts_dedups_and_invokes():
    calls = []
    reg = make_registry(calls)
    rec = Record(
        dirty=True,
        array=[(5, 2), (3, 9), (5, 2), (3, 1), (5, 1)],
        array_capacity_pairs=5,
        callback_fn=6, callback_arg0=1, callback_arg1=2,
    )
    events = flush_and_destroy(rec, reg)
    assert rec.array == [(3, 1), (3, 9), (5, 1), (5, 2)]
    assert rec.array_end_pairs == 4
    assert events[0] == ("flag_cleared",)
    array_calls = [e for e in events if e[0] == "array_callback"]
    assert array_calls == [
        ("array_callback", 3, 1),
        ("array_callback", 3, 9),
        ("array_callback", 5, 1),
        ("array_callback", 5, 2),
    ]
    # Array callbacks precede the list drain, which precedes array free.
    assert events.index(array_calls[-1]) < events.index(
        ("list_callback", 1, 2, 6)) < events.index(("array_freed", 80))
    assert calls == [(1, 3), (9, 3), (1, 5), (2, 5), (6, 1, 2)]
    assert events[-1] == ("inner_deleted", 0xE8)


def test_dirty_large_array_sorts():
    calls = []
    rec = Record(
        dirty=True,
        array=[(i % 7, i % 5 + 1) for i in range(40, 0, -1)],
        array_capacity_pairs=40,
    )
    events = flush_and_destroy(rec, make_registry(calls))
    got = [e[1:] for e in events if e[0] == "array_callback"]
    assert got == sorted(set(got))
    assert len(got) == len(set((a, f) for a, f in got))


def test_clean_path_null_head_leaks_tail():
    calls = []
    rec = Record(
        dirty=False,
        callback_fn=None,
        callback_tail=[CallbackNode(5, 1, 2)],
    )
    events = flush_and_destroy(rec, make_registry(calls))
    # 0x541cab0 returns early on a null head fn: tail untouched.
    assert ("list_callback", 1, 2, 5) not in events
    assert ("list_node_freed", 0x20) not in events
    assert calls == []
    assert rec.callback_tail  # still present: leaked, not freed


def test_dirty_null_head_zeroes_tail_pointer_without_freeing():
    calls = []
    rec = Record(
        dirty=True,
        callback_fn=None,
        callback_tail=[CallbackNode(5, 1, 2)],
    )
    events = flush_and_destroy(rec, make_registry(calls))
    assert ("list_node_freed", 0x20) not in events
    assert calls == []
    assert rec.callback_fn is None
    assert rec.callback_tail == []  # pointer zeroed, nodes orphaned


def test_tree_teardown_order():
    calls = []
    # root: child chain root->c1->c2, successor s1 with child sc.
    sc = TreeNode()
    s1 = TreeNode(child=sc)
    c2 = TreeNode()
    c1 = TreeNode(child=c2, successor=s1)
    root = TreeNode(child=c1)
    rec = Record(tree_nodes=[root])
    events = flush_and_destroy(rec, make_registry(calls))
    freed = [e for e in events if e[0] in
             ("tree_node_freed", "tree_list_node_freed")]
    # Children before parents, successors after the whole subtree:
    # c2, c1, sc, s1, root, then the list node itself.
    assert freed == [("tree_node_freed", 0x28)] * 5 + [
        ("tree_list_node_freed", 0x28)]


def test_tree_list_roots_in_order():
    rec = Record(tree_nodes=[TreeNode(), TreeNode(child=TreeNode())])
    events = flush_and_destroy(rec, make_registry([]))
    freed = [e for e in events if e[0].startswith("tree_")]
    assert freed == [("tree_node_freed", 0x28),
                     ("tree_list_node_freed", 0x28),
                     ("tree_node_freed", 0x28),
                     ("tree_node_freed", 0x28),
                     ("tree_list_node_freed", 0x28)]


def test_vector_order_and_null_skips():
    rec = Record(vec_a=None, vec_b=8, vec_c=None)
    events = flush_and_destroy(rec, make_registry([]))
    assert [e for e in events if e[0] == "vector_freed"] == [
        ("vector_freed", "vec_b", 8)]


def test_packet_records_bind_digest():
    import hashlib
    import json
    root = os.path.join(os.path.dirname(__file__), "..")
    packet = os.path.join(root, "research", "work-items",
                          "RE-001-callback-flush-teardown-94")
    with open(os.path.join(packet, "records.json")) as f:
        records = json.load(f)
    digest = hashlib.sha256(
        open(os.path.join(root, "work", "hl-node-94.bin"), "rb").read()
    ).hexdigest()
    assert records["artifact"]["sha256"] == digest
    assert records["window"]["start"] == "0x5165b80"
    assert records["census"]["direct_calls"] == []
    assert records["census"]["qword_slots"] == ["0x575b310"]


def test_packet_checker_passes():
    root = os.path.join(os.path.dirname(__file__), "..")
    packet = os.path.join(root, "research", "work-items",
                          "RE-001-callback-flush-teardown-94")
    out = subprocess.run(
        [sys.executable, os.path.join(packet, "verify.py")],
        cwd=root, capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "ALL CHECKS PASSED" in out.stdout


def test_entry_bytes_match_raw_binary():
    data = open(os.path.join(os.path.dirname(__file__), "..",
                             "work", "hl-node-94.bin"), "rb").read()
    # objdump VA -> file offset is VA - 0x1000 (verified in the packet).
    assert data[0x5165B80 - 0x1000:0x5165B80 - 0x1000 + 4] == bytes.fromhex(
        "f30f1efa")  # endbr64 at the window entry


TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def main():
    failures = []
    for test in TESTS:
        try:
            test()
            print("PASS %s" % test.__name__)
        except Exception as exc:  # noqa: BLE001 - report and continue
            failures.append(test.__name__)
            print("FAIL %s: %s" % (test.__name__, exc))
    if failures:
        print("FAILURES: %s" % ", ".join(failures))
        return 1
    print("ALL TESTS PASSED (%d)" % len(TESTS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
