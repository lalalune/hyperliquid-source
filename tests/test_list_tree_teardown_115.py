"""Model tests for node #115's recursive list-tree teardown 0x5d4c8d0."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from list_tree_teardown_115 import destroy_list

CHECKS = []


def check(name, actual, expected):
    if actual != expected:
        raise AssertionError("%s: got %r, want %r" % (name, actual, expected))
    CHECKS.append(name)


def expect_raise(name, fn):
    try:
        fn()
    except ValueError:
        CHECKS.append(name)
        return
    raise AssertionError("%s: expected ValueError" % name)


def main():
    check("null head", destroy_list(0, {}), [])
    check("single node", destroy_list(0x1000, {0x1000: {"next": 0, "child": 0}}),
          [(0x1000, 0x30)])
    # Child list destroyed before the node, sibling after it.
    nodes = {
        0x1000: {"next": 0x2000, "child": 0x3000},
        0x2000: {"next": 0, "child": 0},
        0x3000: {"next": 0, "child": 0},
    }
    check("child then node then sibling",
          destroy_list(0x1000, nodes),
          [(0x3000, 0x30), (0x1000, 0x30), (0x2000, 0x30)])
    # Child list with a sibling: the first child is deleted, then
    # the sibling's child, then the sibling, then the parent.
    nodes = {
        0x1000: {"next": 0, "child": 0x3000},
        0x3000: {"next": 0x4000, "child": 0},
        0x4000: {"next": 0, "child": 0x5000},
        0x5000: {"next": 0, "child": 0},
    }
    check("child-list sibling order",
          destroy_list(0x1000, nodes),
          [(0x3000, 0x30), (0x5000, 0x30), (0x4000, 0x30), (0x1000, 0x30)])
    # Ten-deep +0x18 nesting: deeper than the binary's eight
    # inlined levels, so the recursion arm is exercised too.
    # Post-order: innermost first, outermost last.
    nodes = {}
    base = 0x1000
    for i in range(10):
        nodes[base + i * 0x100] = {
            "next": 0,
            "child": base + (i + 1) * 0x100 if i < 9 else 0,
        }
    check("ten-deep nesting",
          destroy_list(base, nodes),
          [(base + i * 0x100, 0x30) for i in range(9, -1, -1)])
    # Deep nesting with a sibling at the deepest level.
    nodes = {}
    for i in range(10):
        nodes[base + i * 0x100] = {
            "next": 0,
            "child": base + (i + 1) * 0x100 if i < 9 else 0x9000,
        }
    nodes[0x9000] = {"next": 0x9100, "child": 0}
    nodes[0x9100] = {"next": 0, "child": 0}
    tail = [(base + i * 0x100, 0x30) for i in range(9, -1, -1)]
    check("deep nesting with deepest sibling",
          destroy_list(base, nodes),
          [(0x9000, 0x30), (0x9100, 0x30)] + tail)
    expect_raise("missing node",
                 lambda: destroy_list(0x1000, {0x1000: {"next": 0x2000, "child": 0}}))
    expect_raise("dangling child",
                 lambda: destroy_list(0x1000, {0x1000: {"next": 0, "child": 0x2000}}))
    expect_raise("missing field",
                 lambda: destroy_list(0x1000, {0x1000: {"next": 0}}))
    expect_raise("child cycle",
                 lambda: destroy_list(0x1000, {
                     0x1000: {"next": 0, "child": 0x2000},
                     0x2000: {"next": 0, "child": 0x1000}}))
    expect_raise("sibling cycle",
                 lambda: destroy_list(0x1000, {
                     0x1000: {"next": 0x2000, "child": 0},
                     0x2000: {"next": 0x1000, "child": 0}}))
    print("%d checks passed" % len(CHECKS))


if __name__ == "__main__":
    main()
