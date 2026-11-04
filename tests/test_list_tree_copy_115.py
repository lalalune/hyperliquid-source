"""Model tests for node #115's recursive list-tree copy 0x5d4caa0."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from list_tree_copy_115 import CopyFailed, copy_list, site_tails

CHECKS = []


def check(name, actual, expected):
    if actual != expected:
        raise AssertionError("%s: got %r, want %r" % (name, actual, expected))
    CHECKS.append(name)


def expect_raise(name, exception, fn):
    try:
        fn()
    except exception:
        CHECKS.append(name)
        return
    raise AssertionError("%s: expected %s" % (name, exception.__name__))


def sequential_alloc(start=0x1000, step=0x100, fail_after=None):
    state = {"count": 0, "order": []}

    def alloc():
        state["count"] += 1
        if fail_after is not None and state["count"] > fail_after:
            raise RuntimeError("out of memory")
        address = start + (state["count"] - 1) * step
        state["order"].append(address)
        return address

    return alloc, state


def worked_tree():
    # Head A with next B and child list C -> D (D having child E).
    return {
        0x1000: {"w0": 0xA1, "tail": bytes(range(16)),
                 "next": 0x2000, "child": 0x3000},
        0x2000: {"w0": 0xB2, "tail": bytes([0xFF] * 16),
                 "next": 0, "child": 0},
        0x3000: {"w0": 0xC3, "tail": bytes([1] * 16),
                 "next": 0x4000, "child": 0},
        0x4000: {"w0": 0xD4, "tail": bytes([2] * 16),
                 "next": 0, "child": 0x5000},
        0x5000: {"w0": 0xE5, "tail": bytes([3] * 16),
                 "next": 0, "child": 0},
    }


def main():
    expect_raise("null head raises",
                 ValueError, lambda: copy_list(0, {}, 0, lambda: 0x1000))
    # Single node: fields copied, links set, gap bytes absent.
    alloc, _ = sequential_alloc()
    head, copies = copy_list(
        0x1000,
        {0x1000: {"w0": 0x12345678, "tail": b"0123456789abcdef",
                  "next": 0, "child": 0}},
        0xDEAD, alloc)
    check("single head", head, 0x1000)
    check("single entry",
          copies[0x1000],
          {"w0": 0x12345678, "tail": b"0123456789abcdef",
           "prev": 0xDEAD, "next": 0, "child": 0})
    # Worked tree: structure, links, and allocation order.
    nodes = worked_tree()
    snapshot = {k: dict(v) for k, v in nodes.items()}
    alloc, state = sequential_alloc()
    head, copies = copy_list(0x1000, nodes, 0xBEEF, alloc)
    check("worked head", head, 0x1000)
    check("allocation order", state["order"],
          [0x1000, 0x1100, 0x1200, 0x1300, 0x1400])
    # Copy addresses follow allocation order: A, C, D, E, B.
    a, c, d, e, b = 0x1000, 0x1100, 0x1200, 0x1300, 0x1400
    check("head links", (copies[a]["prev"], copies[a]["next"],
                         copies[a]["child"]), (0xBEEF, b, c))
    check("sibling prev", copies[b]["prev"], a)
    check("child prev", copies[c]["prev"], a)
    check("child sibling prev", copies[d]["prev"], c)
    check("grandchild prev", copies[e]["prev"], d)
    check("grandchild chain", copies[d]["child"], e)
    check("w0 copied", (copies[a]["w0"], copies[b]["w0"],
                        copies[c]["w0"], copies[d]["w0"], copies[e]["w0"]),
          (0xA1, 0xB2, 0xC3, 0xD4, 0xE5))
    check("tail copied", copies[a]["tail"], bytes(range(16)))
    check("source untouched", nodes, snapshot)
    check("site tails", site_tails(copies, head), (b, c))
    check("site tails single", site_tails(
        {0x1000: {"w0": 1, "tail": bytes(16), "prev": 0,
                  "next": 0, "child": 0}}, 0x1000), (0x1000, 0x1000))
    # Ten-deep child nesting: innermost copy links back up.
    deep = {}
    base = 0x1000
    for i in range(10):
        deep[base + i * 0x100] = {
            "w0": i, "tail": bytes([i] * 16), "next": 0,
            "child": base + (i + 1) * 0x100 if i < 9 else 0}
    alloc, _ = sequential_alloc()
    head, copies = copy_list(base, deep, 0, alloc)
    check("deep head child", copies[head]["child"], head + 0x100)
    check("deep deepest prev",
          copies[head + 9 * 0x100]["prev"], head + 8 * 0x100)
    # Structural guards.
    expect_raise("missing node", ValueError,
                 lambda: copy_list(0x1000, {}, 0, lambda: 0x1000))
    expect_raise("missing field", ValueError,
                 lambda: copy_list(
                     0x1000, {0x1000: {"w0": 1, "tail": bytes(16),
                                      "next": 0}}, 0, lambda: 0x1000))
    expect_raise("bad tail length", ValueError,
                 lambda: copy_list(
                     0x1000, {0x1000: {"w0": 1, "tail": b"short",
                                      "next": 0, "child": 0}},
                     0, lambda: 0x1000))
    expect_raise("sibling cycle", ValueError,
                 lambda: copy_list(
                     0x1000,
                     {0x1000: {"w0": 1, "tail": bytes(16),
                               "next": 0x2000, "child": 0},
                      0x2000: {"w0": 2, "tail": bytes(16),
                               "next": 0x1000, "child": 0}},
                     0, sequential_alloc()[0]))
    expect_raise("child cycle", ValueError,
                 lambda: copy_list(
                     0x1000,
                     {0x1000: {"w0": 1, "tail": bytes(16),
                               "next": 0, "child": 0x2000},
                      0x2000: {"w0": 2, "tail": bytes(16),
                               "next": 0, "child": 0x1000}},
                     0, sequential_alloc()[0]))
    # Allocation failure inside a child list: the inner head copy
    # is torn down first, then the outer head copy.
    nodes = {
        0x1000: {"w0": 1, "tail": bytes(16), "next": 0, "child": 0x3000},
        0x3000: {"w0": 3, "tail": bytes(16), "next": 0x4000, "child": 0},
        0x4000: {"w0": 4, "tail": bytes(16), "next": 0, "child": 0},
    }
    alloc, _ = sequential_alloc(fail_after=2)
    try:
        copy_list(0x1000, nodes, 0, alloc)
        raise AssertionError("child-list failure: expected CopyFailed")
    except CopyFailed as exc:
        check("child-list failure deletes", exc.deletes,
              [(0x1100, 0x30), (0x1000, 0x30)])
    # Allocation failure on a sibling: only the head copy is torn down.
    nodes = {
        0x1000: {"w0": 1, "tail": bytes(16), "next": 0x2000, "child": 0},
        0x2000: {"w0": 2, "tail": bytes(16), "next": 0, "child": 0},
    }
    alloc, _ = sequential_alloc(fail_after=1)
    try:
        copy_list(0x1000, nodes, 0, alloc)
        raise AssertionError("sibling failure: expected CopyFailed")
    except CopyFailed as exc:
        check("sibling failure deletes", exc.deletes, [(0x1000, 0x30)])
    # Failure on the very first allocation: no head copy exists.
    alloc, _ = sequential_alloc(fail_after=0)
    try:
        copy_list(0x1000, nodes, 0, alloc)
        raise AssertionError("first failure: expected CopyFailed")
    except CopyFailed as exc:
        check("first failure deletes", exc.deletes, [])
    print("%d checks passed" % len(CHECKS))


if __name__ == "__main__":
    main()
