"""Tests for the node #115 chain-walk model (0x5d51ea0).

Target-grounded expectations: the both-zero gate and its exact
zeroed bytes, the setup argument order, the sentinel/differing
slot walk (first differing node wins, fifth node unconditional),
the SSO disposal rule, and the input guards. Run from the
repository root:

    python3 tests/test_chain_walk_51ea0_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from chain_walk_51ea0_115 import (MAX_NODES, SENTINEL_ADDRESS, Node,
                                  TempString, chain_walk)

CHECKS = []
SENTINEL = 0x1111


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def run(dest, source, sentinel=SENTINEL):
    calls = []
    events = []

    def setup1(field_0x330, src):
        calls.append(("setup1", field_0x330, src is source))
        return "setup1-value"

    def setup2(slot, value):
        calls.append(("setup2", slot, value))
        return TempString("heap-ptr", 7, False)

    def virtual(dst, node, temp):
        calls.append(("virtual", node.name, temp.pointer))

    result = chain_walk(dest, source, sentinel, setup1, setup2,
                        virtual, events)
    return result, events, calls


def source_with(head, f418=1, f420=0):
    return {"field_0x418": f418, "field_0x420": f420,
            "field_0x330": "field-330", "head": head}


def chain(slots):
    head = None
    for name, slot in reversed(list(enumerate(slots))):
        head = Node("n%d" % name, slot, head)
    return head


def main():
    check("sentinel address constant", SENTINEL_ADDRESS == 0x64ED1B8)
    check("max nodes constant", MAX_NODES == 5)

    # 1. Both-zero gate: destination zeroed except bytes 6-7,
    # no calls of any kind.
    dest = bytearray(b"\xaa" * 16)
    result, events, calls = run(dest, source_with(chain([1]), 0, 0))
    check("zero gate returns", result == "returned")
    check("zero gate events",
          events == ["zero path: destination bytes 0-5, 8-15 zeroed"])
    check("zero gate makes no calls", calls == [])
    check("zero gate bytes",
          dest == bytearray(b"\x00" * 6 + b"\xaa\xaa" + b"\x00" * 8))

    # 2. Either gate field non-zero proceeds (both variants).
    for f418, f420 in ((1, 0), (0, 9)):
        _r, events, calls = run(bytearray(16),
                                source_with(chain([9]), f418, f420))
        check("gate variant proceeds", events[0] == "setup1 called (0x60a1500)")
        check("gate variant setup order",
              calls[0] == ("setup1", "field-330", True)
              and calls[1] == ("setup2", "temp-slot", "setup1-value"))

    # 3. First node differing from the sentinel wins at once.
    _r, events, calls = run(bytearray(16),
                            source_with(chain([9, SENTINEL, SENTINEL])))
    check("first differing wins",
          calls[-1] == ("virtual", "n0", "heap-ptr"))
    check("first differing events tail",
          events[-2] == "virtual called on node n0 (vtable slot 0x118)")

    # 4. Equal prefix, then a differing node at each position.
    for pos in (1, 2, 3):
        slots = [SENTINEL] * pos + [7] + [SENTINEL] * (4 - pos)
        _r, events, calls = run(bytearray(16), source_with(chain(slots)))
        check("differing at %d wins" % pos,
              calls[-1] == ("virtual", "n%d" % pos, "heap-ptr"))

    # 5. All five slots equal: the fifth node is called anyway.
    _r, events, calls = run(
        bytearray(16), source_with(chain([SENTINEL] * 5)))
    check("fifth node unconditional",
          calls[-1] == ("virtual", "n4", "heap-ptr"))

    # 6. Heap temp: delete size is capacity + 1; inline: no free.
    _r, events, _c = run(bytearray(16), source_with(chain([3])))
    check("heap delete size", events[-1] == "delete temp pointer size 8")

    def run_inline(dest, source):
        events = []

        def setup2_inline(slot, value):
            return TempString("temp+0x10", 99, True)

        chain_walk(dest, source, SENTINEL,
                   lambda a, s: "v", setup2_inline,
                   lambda d, n, t: None, events)
        return events

    events = run_inline(bytearray(16), source_with(chain([3])))
    check("inline temp no free", events[-1] == "temp inline: no free")

    # 7. Input guards: null source, null head, and a chain that
    # runs out before diverging all raise, before disposal.
    for bad in (None, source_with(None)):
        try:
            run(bytearray(16), bad)
            check("guard raises", False)
        except ValueError:
            check("guard raises", True)
    try:
        run(bytearray(16), source_with(chain([SENTINEL, SENTINEL])))
        check("short chain raises", False)
    except ValueError:
        check("short chain raises", True)

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
