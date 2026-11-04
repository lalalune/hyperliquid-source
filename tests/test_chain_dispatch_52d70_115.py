"""Tests for the node #115 chain resolve-and-dispatch model (0x5d52d70).

Target-grounded expectations: the no-op acquire stub, the +0x1444
counter increment, the five-step handler comparison against the
relocated global (0x5d4b320) and then against each previous handler,
the unconditional fifth-step dispatch, the exact dispatch argument
list, and the input guards. Run from the repository root:

    python3 tests/test_chain_dispatch_52d70_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from chain_dispatch_52d70_115 import (ACQUIRE_CALLEE, ACQUIRE_OFFSET,
                                      COUNTER_OFFSET, DISPATCH_COUNT,
                                      GLOBAL_ADDRESS, GLOBAL_VALUE,
                                      HANDLER_OFFSET, HEAD_OFFSET,
                                      LINK_OFFSET, RSI_TARGET, Node,
                                      Owner, chain_dispatch)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def chain(handlers):
    node = None
    for handler in reversed(handlers):
        node = Node(handler, node)
    return node


def run(head_node, counter=0, previous=GLOBAL_VALUE):
    owner = Owner(head_node, counter, previous)
    events = []
    result = chain_dispatch(owner, events)
    return owner, result, events


def main():
    check("acquire callee", ACQUIRE_CALLEE == 0x60D5390)
    check("acquire offset", ACQUIRE_OFFSET == 0x700)
    check("head offset", HEAD_OFFSET == 0x318)
    check("counter offset", COUNTER_OFFSET == 0x1444)
    check("link offset", LINK_OFFSET == 0x48)
    check("handler offset", HANDLER_OFFSET == 0x170)
    check("global address", GLOBAL_ADDRESS == 0x64ED590)
    check("global relocated value", GLOBAL_VALUE == 0x5D4B320)
    check("rsi target", RSI_TARGET == 0x5DD6060)
    check("dispatch count arg", DISPATCH_COUNT == 2)

    # 1. Head handler differs from the relocated global at once:
    # dispatch H0 with N0, counter incremented exactly once.
    owner, result, events = run(chain([0x6000000, 0x6000000]))
    check("step0 dispatches head",
          result[0] == "dispatched" and result[1] == 0x6000000)
    check("step0 node is head", result[2] is owner.head_node)
    check("step0 counter", owner.counter == 1)
    check("step0 events start with acquire",
          events[0].startswith("acquire stub called"))
    check("step0 dispatch args",
          result[3] == (result[2], RSI_TARGET, owner, 2, 0, 0))

    # 2. Head equals the global, second differs: dispatch H1.
    owner, result, events = run(chain([GLOBAL_VALUE, 0x6001000, 0x6001000]))
    check("step1 dispatches second",
          result[1] == 0x6001000 and result[2] is owner.head_node.link)
    check("step1 counter", owner.counter == 1)
    check("step1 walk event",
          any("step 0" in e and "equals previous" in e for e in events))

    # 3. First difference at step 2: dispatch H2 with N2.
    n = chain([GLOBAL_VALUE, GLOBAL_VALUE, 0x6002000, 0x6002000])
    owner, result, _e = run(n)
    check("step2 dispatches third",
          result[1] == 0x6002000
          and result[2] is owner.head_node.link.link)

    # 4. First difference at step 3: dispatch H3 with N3.
    n = chain([GLOBAL_VALUE, GLOBAL_VALUE, GLOBAL_VALUE, 0x6003000,
               0x6003000])
    owner, result, _e = run(n)
    check("step3 dispatches fourth",
          result[1] == 0x6003000
          and result[2] is owner.head_node.link.link.link)

    # 5. No difference through step 3: step 4 dispatches H4
    # unconditionally, even when H4 equals the previous handler.
    n = chain([GLOBAL_VALUE] * 5)
    owner, result, events = run(n)
    check("step4 dispatches fifth unconditionally",
          result[1] == GLOBAL_VALUE
          and result[2] is owner.head_node.link.link.link.link)
    check("step4 event",
          any("step 4" in e and "unconditionally" in e for e in events))

    # 6. The previous value is a parameter: when the global is
    # taken to equal H0, the walk continues to H1 instead.
    n = chain([0x6004000, 0x6004001])
    owner, result, _e = run(n, previous=0x6004000)
    check("custom previous walks on",
          result[1] == 0x6004001)

    # 7. Dispatch arguments are identical on every path: node,
    # 0x5dd6060, owner, 2, 0, 0.
    for handlers in ([0x6000000], [GLOBAL_VALUE, 0x6001000],
                     [GLOBAL_VALUE] * 5):
        owner, result, _e = run(chain(handlers))
        check("args shape for %d handlers" % len(handlers),
              result[3][1] == RSI_TARGET and result[3][3] == 2
              and result[3][4] == 0 and result[3][5] == 0
              and result[3][2] is owner)

    # 8. Input guards: a null owner raises; a chain that ends
    # before a dispatch raises; a resolved handler of 0 raises
    # instead of dispatching to address 0.
    try:
        chain_dispatch(None, [])
        check("null owner raises", False)
    except ValueError:
        check("null owner raises", True)
    try:
        run(chain([GLOBAL_VALUE]))
        check("short chain raises", False)
    except ValueError:
        check("short chain raises", True)
    try:
        run(chain([GLOBAL_VALUE] * 4 + [0]))
        check("zero handler raises", False)
    except ValueError:
        check("zero handler raises", True)
    try:
        run(None)
        check("null head node raises", False)
    except ValueError:
        check("null head node raises", True)

    print("%d checks pass" % len(CHECKS))


if __name__ == "__main__":
    main()
