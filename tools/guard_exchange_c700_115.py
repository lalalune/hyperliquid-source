"""Python model of node #115's guard value-exchange chain: the
acquire wrapper 0x607c700, the release wrapper 0x607c720, the
exchange core 0x607c3b0, the exchange 0x6078810 and the gated
TLS-object getter 0x6078650.

Implements the semantics pinned by
research/work-items/RE-001-guard-exchange-c700-115. The chain is
closed: none of the five windows calls anything outside the chain,
and there are no PLT calls.

State shapes (all plain dicts, no binary layout):

- A thread state is ``{"gate": value, "object": object_or_None}``:
  ``gate`` mirrors the qword at thread-pointer - 0x30 (only its
  zero-ness is ever tested; the value is passed on to the exchange,
  which never dereferences it), ``object`` mirrors the qword at
  thread-pointer - 0x38.
- An object is ``{"flag": int, "field30": int}``: ``flag`` is the
  byte at object + 0x00, ``field30`` the 32-bit dword at
  object + 0x30 that the exchange swaps.
- A guard slot is ``{"value": int}``, mirroring the 4-byte stack
  slot each caller passes to the two wrappers.

Model-side guards (not binary behavior, stated explicitly): the
binary performs no range checks and would fault on a dangling
pointer. The model raises ValueError when a flag is outside
0..255 or an exchanged value is outside 0..2**32 - 1, so the model
always stays consistent; tests pin the guards.
"""

MASK32 = (1 << 32) - 1


def _check_u32(value, name):
    if not 0 <= value <= MASK32:
        raise ValueError("%s out of dword range: %r" % (name, value))


def _check_flag(value):
    if not 0 <= value <= 255:
        raise ValueError("flag out of byte range: %r" % (value,))


def gated_object(state):
    """Gated TLS-object getter 0x6078650.

    Returns the object at thread-pointer - 0x38, or None when the
    slot is 0 or the object's flag byte at + 0x00 is 0. Reads and
    writes nothing else.
    """
    obj = state["object"]
    if obj is None:
        return None
    _check_flag(obj["flag"])
    if obj["flag"] == 0:
        return None
    return obj


def exchange(state, value):
    """Exchange 0x6078810.

    Asks the gated getter for the object; when there is none,
    returns 0 and writes nothing. Otherwise atomically swaps
    ``value`` with the dword at object + 0x30 (the binary uses
    ``xchg``, which is always locked against a memory operand) and
    returns the previous dword. The first argument the core passes
    (the gate qword) is accepted here only through ``state`` and is
    never dereferenced, exactly as in the binary.
    """
    _check_u32(value, "value")
    obj = gated_object(state)
    if obj is None:
        return 0
    old = obj["field30"]
    obj["field30"] = value
    return old


def guard_exchange(state, value):
    """Exchange core 0x607c3b0.

    When the qword at thread-pointer - 0x30 is 0, returns 0 and
    touches nothing. Otherwise tail-jumps to the exchange with the
    same value; the gate qword is forwarded as the exchange's first
    argument, which the exchange never dereferences.
    """
    _check_u32(value, "value")
    if not state["gate"]:
        return 0
    return exchange(state, value)


def acquire(state, slot, value):
    """Acquire wrapper 0x607c700.

    Stores the result of ``guard_exchange(state, value)`` -- the
    dword displaced from the object's + 0x30 field, or 0 when a
    gate is closed -- into the caller's 4-byte slot. Callers pass
    small constants (9 in the element-prepare caller mapped by
    RE-001-element-prepare-115, 5 at call site 0x5e00207).
    """
    slot["value"] = guard_exchange(state, value)


def release(state, slot):
    """Release wrapper 0x607c720.

    Returns ``guard_exchange(state, slot["value"])``: it exchanges
    the value saved in the slot back into the object's + 0x30 field
    and yields the dword displaced by that exchange. At all 22
    binary call sites the returned dword is not consumed (the
    instruction after each call reloads the caller's stack canary
    or continues with unrelated state).
    """
    return guard_exchange(state, slot["value"])
