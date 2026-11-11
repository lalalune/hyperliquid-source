"""Tests for the node #115 value transition model (0x5a2f550).

Target-grounded expectations: the four jump-table states, the
zero-value arm, the helper arm with its tag-gated counted-field
release and its flag-selected destructor, the forwarded second
argument, and the two resume guards. Run from the repository
root:

    python3 tests/test_async_value_transition_2f550_115.py
"""

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from async_value_transition_2f550_115 import (
    ARC_DTOR_FLAG_CLEAR, ARC_DTOR_FLAG_SET, CLEANUP_SLOT,
    COPY_OFFSET, FIELD28_OFFSET, FLAG_OFFSET, GLOBAL_CELL,
    GLOBAL_CELL_VALUE, GUARD_COMPLETION, GUARD_MESSAGE_COMPLETION,
    GUARD_MESSAGE_PANICKING, GUARD_PANICKING, HELPER, JUMP_TABLE,
    RELEASE, ROUTINE, SLOT_OFFSET, STATE_OFFSET, TABLE_TARGETS,
    TAG_OFFSET, VALUE_OFFSET, Env, transition)

CHECKS = []


def check(name, condition):
    if not condition:
        raise AssertionError("failed: %s" % name)
    CHECKS.append(name)


def run(env, helper, arg="ctx"):
    events = []
    outcome = transition(env, helper, arg, events)
    return outcome, events


def helper_true(env, arg, events):
    events.append("helper saw arg %r" % (arg,))
    return True


def helper_false(env, arg, events):
    return False


def helper_false_tag3(env, arg, events):
    env.tag = 3
    return False


def main():
    check("routine address", ROUTINE == 0x5A2F550)
    check("jump table", JUMP_TABLE == 0x938F54)
    check("table targets", TABLE_TARGETS == (0x5A2F571, 0x5A2F60E,
                                             0x5A2F601, 0x5A2F597))
    check("offsets", (VALUE_OFFSET, COPY_OFFSET, SLOT_OFFSET,
                      FLAG_OFFSET, TAG_OFFSET, STATE_OFFSET)
          == (0x0, 0x8, 0x10, 0x18, 0x88, 0x90))
    check("field28 offset", FIELD28_OFFSET == 0x28)
    check("helper", HELPER == 0x5A2F760)
    check("release", RELEASE == 0x5A52490)
    check("cleanup slot callee", CLEANUP_SLOT == 0x5A55E70)
    check("guards", (GUARD_COMPLETION, GUARD_PANICKING)
          == (0x1681E60, 0x1681E80))
    check("global cell", (GLOBAL_CELL, GLOBAL_CELL_VALUE)
          == (0x64B8130, 0x4326C1))
    check("dtors", (ARC_DTOR_FLAG_SET, ARC_DTOR_FLAG_CLEAR)
          == (0x5CE8DA0, 0x5CE86D0))

    # 1. State 0, value +0.0: copy is written, helper is not
    # called, state becomes 1, return 0.
    env = Env(value=0.0)
    outcome, events = run(env, helper_true)
    check("zero returns 0", outcome == ("returned", 0))
    check("zero state 1", env.state == 1)
    check("zero copy written", env.copy == 0.0)
    check("zero slot untouched", env.slot is None)
    check("zero helper not called",
          not any("helper" in e and "called" in e for e in events))

    # 2. State 0, value -0.0 compares equal to 0.0: same arm.
    env = Env(value=-0.0)
    outcome, events = run(env, helper_true)
    check("minus zero returns 0", outcome == ("returned", 0)
          and env.state == 1)

    # 3. State 0, NaN is unordered: takes the value arm.
    env = Env(value=math.nan)
    outcome, events = run(env, helper_true)
    check("nan takes value arm", outcome == ("returned", 1)
          and env.state == 3)
    check("nan slot written", math.isnan(env.slot))

    # 4. State 0, nonzero, helper true: slot and copy written,
    # tag cleared before the helper runs, state 3, return 1,
    # second argument forwarded unchanged.
    seen = {}

    def spy_helper(env, arg, events):
        seen["tag_at_call"] = env.tag
        seen["arg"] = arg
        return True

    env = Env(value=2.5, tag=9)
    outcome, events = run(env, spy_helper, arg="CTX-7")
    check("true returns 1", outcome == ("returned", 1))
    check("true state 3", env.state == 3)
    check("true copy and slot", env.copy == 2.5 and env.slot == 2.5)
    check("tag cleared before helper", seen["tag_at_call"] == 0)
    check("second argument forwarded", seen["arg"] == "CTX-7")

    # 5. State 0, helper false, tag stays clear: no release,
    # state 1, return 0.
    env = Env(value=2.5, arc_count=1)
    outcome, events = run(env, helper_false)
    check("false returns 0", outcome == ("returned", 0))
    check("false state 1", env.state == 1)
    check("false no release",
          not any("release field" in e for e in events)
          and env.arc_count == 1)

    # 6. State 0, helper false and the helper leaves tag 3:
    # counter 2 -> 1 (no destructor), field +0x28 released.
    env = Env(value=2.5, arc_count=2, flag=1)
    outcome, events = run(env, helper_false_tag3)
    check("tag3 returns 0", outcome == ("returned", 0))
    check("tag3 counter decremented", env.arc_count == 1)
    check("tag3 no destructor",
          not any("destructor" in e for e in events))
    check("tag3 field28 released",
          any("release field +0x28" in e for e in events))

    # 7. Counter reaching zero calls the flag-selected
    # destructor: flag set -> 0x5ce8da0, flag clear -> 0x5ce86d0.
    env = Env(value=2.5, arc_count=1, flag=1)
    _o, events = run(env, helper_false_tag3)
    check("dtor flag set",
          any("%#x" % ARC_DTOR_FLAG_SET in e for e in events))
    env = Env(value=2.5, arc_count=1, flag=0)
    _o, events = run(env, helper_false_tag3)
    check("dtor flag clear",
          any("%#x" % ARC_DTOR_FLAG_CLEAR in e for e in events))

    # 8. State 3: no copy, no tag clear; the helper sees the
    # tag as stored, and a true verdict keeps state 3.
    seen = {}

    def spy3(env, arg, events):
        seen["tag_at_call"] = env.tag
        return True

    env = Env(value=9.0, tag=7, state=3)
    env.slot = 4.5
    outcome, events = run(env, spy3)
    check("state3 returns 1", outcome == ("returned", 1))
    check("state3 stays 3", env.state == 3)
    check("state3 no copy", env.copy is None)
    check("state3 tag not cleared", seen["tag_at_call"] == 7)
    check("state3 slot untouched", env.slot == 4.5)

    # 9. State 3, helper false with tag 3: releases run and the
    # state becomes 1.
    env = Env(value=9.0, arc_count=1, flag=0, tag=3, state=3)
    outcome, events = run(env, helper_false)
    check("state3 false returns 0", outcome == ("returned", 0))
    check("state3 false state 1", env.state == 1)
    check("state3 false released",
          any("destructor" in e for e in events))

    # 10. State 1: the completion guard fires, the cleanup
    # releases field +0x28, the state becomes 2.
    env = Env(state=1)
    outcome, events = run(env, helper_true)
    check("state1 unwinds", outcome == ("unwind",
                                         GUARD_MESSAGE_COMPLETION))
    check("state1 guard event",
          any("guard %#x" % GUARD_COMPLETION in e for e in events))
    check("state1 cleanup", env.state == 2
          and any("release field +0x28" in e for e in events))

    # 11. State 2: the panicking guard fires first, same
    # cleanup, state stays 2.
    env = Env(state=2)
    outcome, events = run(env, helper_true)
    check("state2 unwinds", outcome == ("unwind",
                                        GUARD_MESSAGE_PANICKING))
    check("state2 guard event",
          any("guard %#x" % GUARD_PANICKING in e for e in events))
    check("state2 cleanup", env.state == 2
          and any("release field +0x28" in e for e in events))

    # 12. A state above 3 is not modelled.
    env = Env(state=4)
    try:
        run(env, helper_true)
        raised = False
    except ValueError:
        raised = True
    check("state 4 raises", raised)

    print("async_value_transition_2f550_115: %d checks pass"
          % len(CHECKS))


if __name__ == "__main__":
    main()
