"""Tests for the node #115 keyed lookup finalize model
(wrapper 0x606c680 + lookup 0x5d52660).

Target-grounded expectations: the wrapper's null-key path,
the lookup's null-out early return, the auxiliary call
before the walk, the lower-bound walk, the value1 <=
field < value2 acceptance range with its boundaries, the
success write and call order, and the input guards. Run
from the repository root:

    python3 tests/test_keyed_lookup_finalize_52660_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from keyed_lookup_finalize_52660_115 import (
    AUX_CALLEE, AUX_OFFSET, AUX_RELEASE_CALLEE, FLAG_OFFSET,
    KEY_OFFSET, LOOKUP, LOOKUP_FDE, NODE_KEY_OFFSET,
    NODE_LEFT_OFFSET, NODE_RIGHT_OFFSET, OUT1_OFFSET,
    OUT2_OFFSET, PAYLOAD_CALLEE, PAYLOAD_OFFSET,
    SLOT_REPLACE_CALL, TAIL_HELPER, TAIL_JUMP_CALLER_FDE,
    TAIL_JUMP_SITE, TREE_HEADER_OFFSET, TREE_ROOT_OFFSET,
    WRAPPER, WRAPPER_FDE, Key, Node, RecordingHooks,
    TreeNode, finalize_6c680, lookup_52660)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def test_constants():
    check("wrapper address", WRAPPER == 0x606C680)
    check("lookup address", LOOKUP == 0x5D52660)
    check("wrapper FDE", WRAPPER_FDE == (0x606C680, 0x606C6A5))
    check("lookup FDE", LOOKUP_FDE == (0x5D52660, 0x5D52765))
    check("key offset", KEY_OFFSET == 0x68)
    check("out1 offset", OUT1_OFFSET == 0x08)
    check("out2 offset", OUT2_OFFSET == 0x20)
    check("flag offset", FLAG_OFFSET == 0x60)
    check("tree header offset", TREE_HEADER_OFFSET == 0xCA8)
    check("tree root offset", TREE_ROOT_OFFSET == 0xCB0)
    check("aux offset", AUX_OFFSET == 0x988)
    check("node left offset", NODE_LEFT_OFFSET == 0x10)
    check("node right offset", NODE_RIGHT_OFFSET == 0x18)
    check("node key offset", NODE_KEY_OFFSET == 0x20)
    check("payload offset", PAYLOAD_OFFSET == 0x28)
    check("aux callee", AUX_CALLEE == 0x606CA40)
    check("aux release callee", AUX_RELEASE_CALLEE == 0x60D52F0)
    check("payload callee", PAYLOAD_CALLEE == 0x5D4E140)
    check("slot replace call site", SLOT_REPLACE_CALL == 0x5D4CD33)
    check("tail jump site", TAIL_JUMP_SITE == 0x606C6D6)
    check("tail jump caller FDE",
          TAIL_JUMP_CALLER_FDE == (0x606C6B0, 0x606C6DB))
    check("tail helper", TAIL_HELPER == 0x606C190)


def test_wrapper_null_node_raises():
    try:
        finalize_6c680(None, 1, 2, RecordingHooks())
    except ValueError:
        check("null node raises", True)
    else:
        check("null node raises", False)


def test_wrapper_null_key_stores_zero_and_calls_nothing():
    hooks = RecordingHooks()
    node = Node(None)
    result = finalize_6c680(node, 10, 20, hooks)
    check("null key returns 0", result == 0)
    check("null key stores 0 at +0x60", node.fields[FLAG_OFFSET] == 0)
    check("null key calls nothing", hooks.events == [])


def test_lookup_null_key_raises():
    try:
        lookup_52660(None, 1, 2, Node(), RecordingHooks())
    except ValueError:
        check("null key raises", True)
    else:
        check("null key raises", False)


def test_lookup_null_out_returns_zero_without_calls():
    key = Key(TreeNode(10))
    node = Node(key)
    for out1, out2 in ((False, True), (True, False), (False, False)):
        hooks = RecordingHooks()
        result = lookup_52660(key, 5, 20, node, hooks,
                              out1_present=out1, out2_present=out2)
        check("null out returns 0", result == 0)
        check("null out calls nothing", hooks.events == [])
        check("null out writes nothing", OUT1_OFFSET not in node.fields)


def tree_10_20_30():
    return Key(TreeNode(20, TreeNode(10), TreeNode(30)))


def test_empty_tree_returns_zero_after_aux_and_release():
    hooks = RecordingHooks()
    node = Node(Key(None))
    result = lookup_52660(node.key, 5, 20, node, hooks)
    check("empty tree returns 0", result == 0)
    check("empty tree call order",
          hooks.events == [("aux_lookup", node.key, 5, 20, node,
                            OUT1_OFFSET, node, OUT2_OFFSET),
                           ("aux_release", node.key)])
    check("empty tree writes nothing", OUT1_OFFSET not in node.fields)


def test_no_candidate_returns_zero():
    hooks = RecordingHooks()
    node = Node(tree_10_20_30())
    result = lookup_52660(node.key, 31, 100, node, hooks)
    check("no candidate returns 0", result == 0)
    check("no candidate releases", hooks.events[-1] == ("aux_release",
                                                        node.key))
    check("no candidate writes nothing", OUT1_OFFSET not in node.fields)


def test_candidate_at_upper_bound_returns_zero():
    hooks = RecordingHooks()
    node = Node(tree_10_20_30())
    result = lookup_52660(node.key, 15, 20, node, hooks)
    check("candidate equal to value2 returns 0", result == 0)
    check("bound equality writes nothing", OUT1_OFFSET not in node.fields)


def test_range_match_writes_and_orders_calls():
    hooks = RecordingHooks()
    node = Node(tree_10_20_30())
    result = lookup_52660(node.key, 15, 25, node, hooks)
    check("range match returns 1", result == 1)
    check("range match writes matched field",
          node.fields[OUT1_OFFSET] == 20)
    candidate = node.key.root
    check("range match call order",
          hooks.events == [("aux_lookup", node.key, 15, 25, node,
                            OUT1_OFFSET, node, OUT2_OFFSET),
                           ("payload", node, OUT2_OFFSET, candidate,
                            PAYLOAD_OFFSET),
                           ("aux_release", node.key)])


def test_lower_bound_picks_smallest_not_below():
    node = Node(tree_10_20_30())
    hooks = RecordingHooks()
    lookup_52660(node.key, 10, 11, node, hooks)
    check("exact value1 matches itself", node.fields[OUT1_OFFSET] == 10)
    node = Node(tree_10_20_30())
    hooks = RecordingHooks()
    lookup_52660(node.key, 21, 100, node, hooks)
    check("value1 between keys picks the next key",
          node.fields[OUT1_OFFSET] == 30)


def test_walk_goes_right_below_and_left_above():
    root = TreeNode(50, TreeNode(30, TreeNode(20), TreeNode(40)),
                    TreeNode(70, TreeNode(60), TreeNode(80)))
    node = Node(Key(root))
    hooks = RecordingHooks()
    lookup_52660(node.key, 55, 100, node, hooks)
    check("walk right then left finds 60", node.fields[OUT1_OFFSET] == 60)
    node = Node(Key(root))
    hooks = RecordingHooks()
    lookup_52660(node.key, 5, 100, node, hooks)
    check("walk left to the smallest finds 20",
          node.fields[OUT1_OFFSET] == 20)


def test_wrapper_stores_lookup_result():
    hooks = RecordingHooks()
    node = Node(tree_10_20_30())
    result = finalize_6c680(node, 15, 25, hooks)
    check("wrapper returns 1 on match", result == 1)
    check("wrapper stores 1 at +0x60", node.fields[FLAG_OFFSET] == 1)
    check("wrapper match also writes +0x08",
          node.fields[OUT1_OFFSET] == 20)
    hooks = RecordingHooks()
    node = Node(tree_10_20_30())
    result = finalize_6c680(node, 15, 20, hooks)
    check("wrapper returns 0 on range failure", result == 0)
    check("wrapper stores 0 at +0x60", node.fields[FLAG_OFFSET] == 0)


def test_unsigned_max_boundaries():
    top = 2 ** 64 - 1
    node = Node(Key(TreeNode(top - 1)))
    hooks = RecordingHooks()
    result = lookup_52660(node.key, 5, top, node, hooks)
    check("max-1 field below max bound matches", result == 1)
    check("max-1 field written",
          node.fields[OUT1_OFFSET] == top - 1)
    node = Node(Key(TreeNode(top)))
    hooks = RecordingHooks()
    result = lookup_52660(node.key, top, top, node, hooks)
    check("max field equal to max bound fails", result == 0)


def main():
    test_constants()
    test_wrapper_null_node_raises()
    test_wrapper_null_key_stores_zero_and_calls_nothing()
    test_lookup_null_key_raises()
    test_lookup_null_out_returns_zero_without_calls()
    test_empty_tree_returns_zero_after_aux_and_release()
    test_no_candidate_returns_zero()
    test_candidate_at_upper_bound_returns_zero()
    test_range_match_writes_and_orders_calls()
    test_lower_bound_picks_smallest_not_below()
    test_walk_goes_right_below_and_left_above()
    test_wrapper_stores_lookup_result()
    test_unsigned_max_boundaries()
    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
