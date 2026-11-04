"""Model tests for the node #115 vector destructor at 0x5d5e220.

Run from the repository root:
    python3 tests/test_vector_destructor_115.py
Prints "checks pass" with the count on success, else raises.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from vector_destructor_115 import (Node, StringField, destroy_vector,
                                   ELEMENT_STRIDE)

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


def main():
    # Empty vector, no storage: nothing happens.
    check(destroy_vector({"begin_present": False, "elements": [],
                          "capacity_bytes": None}) == [],
          "null begin destroys nothing")
    # Empty vector, storage present: only the storage is freed.
    check(destroy_vector({"begin_present": True, "elements": [],
                          "capacity_bytes": 0x7E0})
          == [("delete-storage", 0x7E0)], "empty allocated vector frees storage")
    # One element, all inline strings, empty trees: storage only.
    check(destroy_vector({"begin_present": True, "elements": [element()],
                          "capacity_bytes": ELEMENT_STRIDE})
          == [("delete-storage", ELEMENT_STRIDE)],
          "single inline element leaves storage only")
    # Heap strings use cap + 1, in field order, storage last.
    strings = inline_strings()
    strings[0x3B8] = StringField("heap", 5)
    strings[0x368] = StringField("heap", 0)
    strings[0x00] = StringField("heap", 15)
    out = destroy_vector({"begin_present": True, "elements": [element(strings=strings)],
                          "capacity_bytes": ELEMENT_STRIDE})
    check(out == [("delete-string", "0x3b8", 6),
                  ("delete-string", "0x368", 1),
                  ("delete-string", "0x0", 16),
                  ("delete-storage", ELEMENT_STRIDE)],
          "heap string order and cap+1 sizes: %r" % (out,))
    # Worked tree: head A with child chain C -> D (D child E) and
    # sibling B, in the first list; second list empty.
    e = Node("E")
    d = Node("D", child=e)
    c = Node("C", nxt=d)
    b = Node("B")
    a = Node("A", child=c, nxt=b,
             str_a=StringField("heap", 3), str_b=StringField("heap", 7))
    out = destroy_vector({"begin_present": True,
                          "elements": [element(trees={0x318: a, 0x2E8: None})],
                          "capacity_bytes": ELEMENT_STRIDE})
    check(out == [("delete-node", "C", 0x60),
                  ("delete-node", "E", 0x60),
                  ("delete-node", "D", 0x60),
                  ("delete-string-B", "A", 8),
                  ("delete-string-A", "A", 4),
                  ("delete-node", "A", 0x60),
                  ("delete-node", "B", 0x60),
                  ("delete-storage", ELEMENT_STRIDE)],
          "worked tree order: %r" % (out,))
    # Both lists, in order: first list before second list.
    first = Node("F1")
    second = Node("S1", str_b=StringField("heap", 1))
    out = destroy_vector({"begin_present": True,
                          "elements": [element(trees={0x318: first, 0x2E8: second})],
                          "capacity_bytes": ELEMENT_STRIDE})
    check(out == [("delete-node", "F1", 0x60),
                  ("delete-string-B", "S1", 2),
                  ("delete-node", "S1", 0x60),
                  ("delete-storage", ELEMENT_STRIDE)],
          "two-list order: %r" % (out,))
    # Two elements: first element fully before the second, one storage delete.
    s1 = inline_strings()
    s1[0x3B8] = StringField("heap", 0)
    s2 = inline_strings()
    s2[0x00] = StringField("heap", 0)
    out = destroy_vector({"begin_present": True,
                          "elements": [element(strings=s1), element(strings=s2)],
                          "capacity_bytes": 2 * ELEMENT_STRIDE})
    check(out == [("delete-string", "0x3b8", 1),
                  ("delete-string", "0x0", 1),
                  ("delete-storage", 2 * ELEMENT_STRIDE)],
          "two-element order: %r" % (out,))
    # Storage size is the capacity count, not the element count.
    out = destroy_vector({"begin_present": True, "elements": [element()],
                          "capacity_bytes": 4 * ELEMENT_STRIDE})
    check(out == [("delete-storage", 4 * ELEMENT_STRIDE)],
          "storage size uses capacity")
    # Input is not mutated.
    vec = {"begin_present": True, "elements": [element()],
           "capacity_bytes": ELEMENT_STRIDE}
    destroy_vector(vec)
    check(len(vec["elements"]) == 1 and vec["capacity_bytes"] == ELEMENT_STRIDE,
          "input unmutated")
    # Guards: null begin with elements, bad capacity, missing fields,
    # cyclic tree, dangling node.
    for bad, label in [
            ({"begin_present": False, "elements": [element()],
              "capacity_bytes": None}, "null begin with elements"),
            ({"begin_present": True, "elements": [element()],
              "capacity_bytes": 1}, "capacity below element bytes"),
            ({"begin_present": True,
              "elements": [{"trees": {0x318: None}}],
              "capacity_bytes": ELEMENT_STRIDE}, "missing fields"),
    ]:
        try:
            destroy_vector(bad)
        except ValueError:
            pass
        else:
            raise AssertionError("no raise: %s" % label)
        CHECKS[0] += 1
    cyclic = Node("X")
    cyclic.next = cyclic
    try:
        destroy_vector({"begin_present": True,
                        "elements": [element(trees={0x318: cyclic, 0x2E8: None})],
                        "capacity_bytes": ELEMENT_STRIDE})
    except ValueError:
        CHECKS[0] += 1
    else:
        raise AssertionError("no raise: cyclic tree")
    try:
        destroy_vector({"begin_present": True,
                        "elements": [element(trees={0x318: "nope", 0x2E8: None})],
                        "capacity_bytes": ELEMENT_STRIDE})
    except ValueError:
        CHECKS[0] += 1
    else:
        raise AssertionError("no raise: dangling node")
    print("checks pass (%d)" % CHECKS[0])


if __name__ == "__main__":
    main()
