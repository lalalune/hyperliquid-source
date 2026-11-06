"""Model of the node #115 value transition routine at 0x5a2f550.

Transcribed from the digest-verified work binary (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).
The routine is a four-state transition over one environment
object. The state byte at env +0x90 selects the arm through a
four-entry relative jump table at 0x938f54:

  state 0: copy the binary64 at env +0x0 to env +0x8; if it
    compares equal to 0.0 (ordered), store state 1 and return 0.
    Otherwise store it at env +0x10, clear the tag byte at
    env +0x88, and run the helper arm below.
  state 3: run the helper arm directly (no copy, no tag clear).
  helper arm: call the helper (0x5a2f760) with env +0x10 and the
    routine's own second argument forwarded unmodified. If the
    helper returns true, store state 3 and return 1. If it
    returns false and the tag byte is 3 by then, release the
    counted field at env +0x20 (decrement its counter; on zero
    call the destructor selected by the flag byte at env +0x18)
    and release the field at env +0x28 via 0x5a52490; store
    state 1 and return 0 either way.
  state 1: call the completion resume guard (0x1681e60) with the
    global cell 0x64b8130; the guard does not return. Its
    cleanup releases env +0x28, stores state 2, and resumes the
    unwind. Modelled as an ("unwind", message) outcome.
  state 2: call the panicking resume guard (0x1681e80) first,
    then the same cleanup and resume as state 1.

States above 3 are not modelled: the binary would dispatch
through table slots past the four in-window entries, and no
caller-visible write of such a state is pinned.
"""

ROUTINE = 0x5A2F550
ROUTINE_FDE = (0x5A2F550, 0x5A2F661)
JUMP_TABLE = 0x938F54
TABLE_TARGETS = (0x5A2F571, 0x5A2F60E, 0x5A2F601, 0x5A2F597)

VALUE_OFFSET = 0x0
COPY_OFFSET = 0x8
SLOT_OFFSET = 0x10
FLAG_OFFSET = 0x18
ARC_OFFSET = 0x20
FIELD28_OFFSET = 0x28
TAG_OFFSET = 0x88
STATE_OFFSET = 0x90

HELPER = 0x5A2F760
HELPER_FDE = (0x5A2F760, 0x5A2FA70)
RELEASE = 0x5A52490
RELEASE_FDE = (0x5A52490, 0x5A52518)
CLEANUP_SLOT = 0x5A55E70

ARC_DTOR_FLAG_SET = 0x5CE8DA0    # via GOT slot 0x64dfdc8
ARC_DTOR_FLAG_CLEAR = 0x5CE86D0  # via GOT slot 0x64dfdb8

GLOBAL_CELL = 0x64B8130
GLOBAL_CELL_VALUE = 0x4326C1
GUARD_COMPLETION = 0x1681E60     # via GOT slot 0x64e1368
GUARD_PANICKING = 0x1681E80      # via GOT slot 0x64e1360
GUARD_MESSAGE_COMPLETION = "`async fn` resumed after completion"
GUARD_MESSAGE_PANICKING = "`async fn` resumed after panicking"


class Env:
    """The environment object the routine transitions."""

    def __init__(self, value=0.0, flag=0, arc_count=1, tag=0,
                 state=0):
        self.value = value        # binary64 at +0x0
        self.copy = None          # binary64 at +0x8 (None = unwritten)
        self.slot = None          # binary64 at +0x10 (None = unwritten)
        self.flag = flag          # byte at +0x18
        self.arc_count = arc_count  # counter cell behind +0x20
        self.tag = tag            # byte at +0x88
        self.state = state        # byte at +0x90


def _release_field28(env, events):
    events.append("release field +0x28 via %#x" % RELEASE)


def _guard_unwind(env, events, guard, message):
    events.append("guard %#x called with global cell %#x"
                  % (guard, GLOBAL_CELL))
    _release_field28(env, events)
    env.state = 2
    events.append("state := 2; resume unwind")
    return ("unwind", message)


def _helper_arm(env, helper, arg, events):
    events.append("helper %#x called with env +0x10 and the "
                  "forwarded second argument" % HELPER)
    if helper(env, arg, events):
        env.state = 3
        events.append("state := 3")
        return ("returned", 1)
    if env.tag == 3:
        env.arc_count -= 1
        events.append("arc counter at +0x20 decremented to %d"
                      % env.arc_count)
        if env.arc_count == 0:
            dtor = (ARC_DTOR_FLAG_SET if env.flag != 0
                    else ARC_DTOR_FLAG_CLEAR)
            events.append("arc destructor %#x called" % dtor)
        _release_field28(env, events)
    env.state = 1
    events.append("state := 1")
    return ("returned", 0)


def transition(env, helper, arg, events):
    """Run one transition of the routine at 0x5a2f550.

    helper is the verdict callable for 0x5a2f760: it receives
    (env, arg, events), may rewrite env.tag, and returns a bool.
    arg is the routine's second argument, forwarded to the
    helper unmodified and otherwise unread. Returns
    ("returned", 0|1) or ("unwind", guard message).
    """
    state = env.state
    if state == 0:
        env.copy = env.value
        events.append("copy +0x0 -> +0x8")
        if env.value == 0.0:
            env.state = 1
            events.append("state := 1")
            return ("returned", 0)
        env.slot = env.value
        env.tag = 0
        events.append("store +0x0 -> +0x10; tag := 0")
        return _helper_arm(env, helper, arg, events)
    if state == 3:
        return _helper_arm(env, helper, arg, events)
    if state == 1:
        return _guard_unwind(env, events, GUARD_COMPLETION,
                             GUARD_MESSAGE_COMPLETION)
    if state == 2:
        return _guard_unwind(env, events, GUARD_PANICKING,
                             GUARD_MESSAGE_PANICKING)
    raise ValueError("state byte %#x not modelled" % state)
