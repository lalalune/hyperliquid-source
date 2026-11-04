"""Model tests for the node #115 two-collection element destroy at 0x5d5e860.

Run from the repository root:
    python3 tests/test_count_range_destroy_115.py
Prints "checks pass" with the count on success, else raises.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from count_range_destroy_115 import (Node, StringField,
                                     destroy_counted_and_range)

CHECKS = [0]


def check(condition, label):
    CHECKS[0] += 1
    if not condition:
        raise AssertionError("check failed: %s" % label)


def inline_strings():
    return {off: StringField("inline") for off in
            (0x3B8, 0x398, 0x368, 0x2B8, 0x298, 0x278, 0x258, 0x238,
             0x218, 0x1F8, 0x1D8, 0x1B8, 0x198, 0x178, 0x158,
             0x40, 0x20, 0x00)}


def element(trees=None, strings=None):
    return {"trees": trees if trees is not None else {0x318: None, 0x2E8: None},
            "strings": strings if strings is not None else inline_strings()}


def obj(counted=None, ranged=None, base=True, begin=True):
    counted = counted if counted is not None else []
    ranged = ranged if ranged is not None else []
    return {"count": len(counted),
            "counted_base_present": base,
            "counted_elements": counted,
            "range_begin_present": begin,
            "range_elements": ranged}


def main():
    # Empty object: nothing happens, no reset record.
    check(destroy_counted_and_range(obj()) == [],
          "empty object destroys nothing")
    # One counted inline element: drained, no deletes, no reset.
    check(destroy_counted_and_range(obj(counted=[element()])) == [],
          "single inline counted element leaves no deletes")
    # Counted heap strings use cap + 1, in field order.
    strings = inline_strings()
    strings[0x3B8] = StringField("heap", 5)
    strings[0x368] = StringField("heap", 0)
    strings[0x00] = StringField("heap", 15)
    out = destroy_counted_and_range(obj(counted=[element(strings=strings)]))
    check(out == [("delete-string", "0x3b8", 6),
                  ("delete-string", "0x368", 1),
                  ("delete-string", "0x0", 16)],
          "counted heap string order and cap+1 sizes: %r" % (out,))
    # Counted drain is reverse: element 2, then 1, then 0.
    elems = []
    for cap in (0, 1, 2):
        strings = inline_strings()
        strings[0x3B8] = StringField("heap", cap)
        elems.append(element(strings=strings))
    out = destroy_counted_and_range(obj(counted=elems))
    check(out == [("delete-string", "0x3b8", 3),
                  ("delete-string", "0x3b8", 2),
                  ("delete-string", "0x3b8", 1)],
          "counted drain reverse order: %r" % (out,))
    # Range destroy is forward and ends with the end reset.
    elems = []
    for cap in (0, 1):
        strings = inline_strings()
        strings[0x00] = StringField("heap", cap)
        elems.append(element(strings=strings))
    out = destroy_counted_and_range(obj(ranged=elems))
    check(out == [("delete-string", "0x0", 1),
                  ("delete-string", "0x0", 2),
                  ("reset-range-end", "begin")],
          "range forward order plus end reset: %r" % (out,))
    # Empty range with a present begin: no reset record.
    check(destroy_counted_and_range(obj(ranged=[], begin=True)) == [],
          "empty range stores no end reset")
    # Both phases: the whole counted drain precedes the range.
    strings = inline_strings()
    strings[0x3B8] = StringField("heap", 9)
    counted_elem = element(strings=strings)
    strings = inline_strings()
    strings[0x00] = StringField("heap", 4)
    ranged_elem = element(strings=strings)
    out = destroy_counted_and_range(
        obj(counted=[counted_elem], ranged=[ranged_elem]))
    check(out == [("delete-string", "0x3b8", 10),
                  ("delete-string", "0x0", 5),
                  ("reset-range-end", "begin")],
          "counted drain precedes range destroy: %r" % (out,))
    # Worked tree: head A with child chain C -> D (D child E) and
    # sibling B, in the first list; second list empty.
    e = Node("E")
    d = Node("D", child=e)
    c = Node("C", nxt=d)
    b = Node("B")
    a = Node("A", child=c, nxt=b,
             str_a=StringField("heap", 3), str_b=StringField("heap", 7))
    out = destroy_counted_and_range(
        obj(counted=[element(trees={0x318: a, 0x2E8: None})]))
    check(out == [("delete-node", "C", 0x60),
                  ("delete-node", "E", 0x60),
                  ("delete-node", "D", 0x60),
                  ("delete-string-B", "A", 8),
                  ("delete-string-A", "A", 4),
                  ("delete-node", "A", 0x60),
                  ("delete-node", "B", 0x60)],
          "worked tree order: %r" % (out,))
    # Both lists, in order: first list before second list.
    first = Node("F1")
    second = Node("S1", str_b=StringField("heap", 1))
    out = destroy_counted_and_range(
        obj(counted=[element(trees={0x318: first, 0x2E8: second})]))
    check(out == [("delete-node", "F1", 0x60),
                  ("delete-string-B", "S1", 2),
                  ("delete-node", "S1", 0x60)],
          "two-list order: %r" % (out,))
    # Field order inside one element: leading strings, trees,
    # trailing strings.
    strings = inline_strings()
    strings[0x398] = StringField("heap", 2)
    strings[0x2B8] = StringField("heap", 6)
    node = Node("N", str_b=StringField("heap", 0))
    out = destroy_counted_and_range(obj(counted=[element(
        trees={0x318: node, 0x2E8: None}, strings=strings)]))
    check(out == [("delete-string", "0x398", 3),
                  ("delete-string-B", "N", 1),
                  ("delete-node", "N", 0x60),
                  ("delete-string", "0x2b8", 7)],
          "element field order: %r" % (out,))
    # No storage delete and no object delete ever appear.
    out = destroy_counted_and_range(
        obj(counted=[element()], ranged=[element()]))
    check(all(kind not in ("delete-storage", "delete-object")
              for kind, *_ in out),
          "no storage or object delete: %r" % (out,))
    # Heap capacity 0 frees exactly 1 byte.
    strings = inline_strings()
    strings[0x40] = StringField("heap", 0)
    out = destroy_counted_and_range(obj(ranged=[element(strings=strings)]))
    check(out == [("delete-string", "0x40", 1),
                  ("reset-range-end", "begin")],
          "heap capacity 0 frees 1 byte: %r" % (out,))
    # Input is not mutated.
    data = obj(counted=[element()], ranged=[element()])
    destroy_counted_and_range(data)
    check(data["count"] == 1 and len(data["counted_elements"]) == 1
          and len(data["range_elements"]) == 1, "input unmutated")
    # Guards: count mismatch, negative count, nonzero count with
    # no base, nonzero range with no begin, missing fields,
    # cyclic tree, dangling node.
    cyclic = Node("X")
    cyclic.next = cyclic
    for bad, label in [
            ({"count": 2, "counted_base_present": True,
              "counted_elements": [element()],
              "range_begin_present": True, "range_elements": []},
             "count mismatch"),
            ({"count": -1, "counted_base_present": True,
              "counted_elements": [],
              "range_begin_present": True, "range_elements": []},
             "negative count"),
            ({"count": 1, "counted_base_present": False,
              "counted_elements": [element()],
              "range_begin_present": True, "range_elements": []},
             "nonzero count with no base"),
            ({"count": 0, "counted_base_present": True,
              "counted_elements": [],
              "range_begin_present": False,
              "range_elements": [element()]},
             "nonzero range with no begin"),
            ({"count": 1, "counted_base_present": True,
              "counted_elements": [{"trees": {0x318: None},
                                    "strings": inline_strings()}],
              "range_begin_present": True, "range_elements": []},
             "missing tree field"),
            ({"count": 1, "counted_base_present": True,
              "counted_elements": [{"trees": {0x318: None, 0x2E8: None},
                                    "strings": {}}],
              "range_begin_present": True, "range_elements": []},
             "missing string field"),
            (obj(counted=[element(trees={0x318: cyclic, 0x2E8: None})]),
             "cyclic tree"),
            (obj(counted=[element(trees={0x318: "bogus", 0x2E8: None})]),
             "dangling node")]:
        try:
            destroy_counted_and_range(bad)
        except ValueError:
            check(True, label)
        else:
            check(False, "guard missed: %s" % label)
    print("%d checks pass" % CHECKS[0])


if __name__ == "__main__":
    main()
