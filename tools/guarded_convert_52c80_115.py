"""Model of node #115 routine 0x5d52c80: guarded element conversion.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes one argument, an owner object pointer in rdi,
and returns one 32-bit value. In order:

1. Acquire: call 0x606ca40 with the member at owner +0x9c8.
   The acquire callee is opaque here; what is pinned is that it
   receives exactly that member, and that the matching release
   call below receives the same member.
2. Select an element pointer P. Load A = qword at owner +0xb50
   and compare it with the qword at owner +0xb58:
   - A != [owner +0xb58]: P = qword at (A - 0x18).
   - A == [owner +0xb58]: load E = qword at owner +0xb68,
     then P = qword at ([E - 8] + 0x200 - 0x18).
3. Convert: call 0x5f03b40 with P. That callee is only 16 bytes
   and is pinned end to end: it loads Q = qword at P and
   returns (Q with its low byte replaced by 1 when the qword
   at Q +0x58 is zero, else 0). The upper bytes of the
   returned eax are NOT cleared: sete writes only %al, so the
   caller receives Q's low 32 bits with the low byte replaced
   by the predicate bit, and returns that value unchanged.
4. Release: call 0x60d52f0 with the same +0x9c8 member. That
   callee calls pthread_mutex_unlock@plt, which is the
   evidence that the +0x9c8 member is a mutex-shaped object.
   The exception path (landing-pad entry at 0x5d52cdc, inside
   the routine FDE range) releases the same member and then
   resumes unwinding via the cleanup block at 0x5d52c70; it is
   documented here, not modelled, because the model has no
   unwinding.

The routine writes nothing to the owner object itself: every
write it performs is to its own stack frame. No removal or
mutation of any element is claimed -- the binary shows no
store to the owner or to any element slot, so "pop" is not
claimed for this routine; the converter callee's own effects
beyond the pinned return computation are not pinned either.

NOT modelled: what the owner, the +0x9c8 member, the slots at
+0xb50/+0xb58/+0xb68, or the elements denote; what the
acquire callee (0x606ca40) does internally; the meaning of
the +0x58 field beyond the zero test; or behaviour on dangling
pointers. A null owner raises, matching the binary's
unconditional reads. An out-of-range selection is not given a
binary behaviour: the binary dereferences unchecked, and the
model raises instead.
"""

MUTEX_OFFSET = 0x9C8
SLOT_A_OFFSET = 0xB50
SLOT_B_OFFSET = 0xB58
SLOT_E_OFFSET = 0xB68
PREDICATE_FIELD_OFFSET = 0x58
ACQUIRE_ROUTINE = 0x606CA40
CONVERT_ROUTINE = 0x5F03B40
RELEASE_ROUTINE = 0x60D52F0
CLEANUP_BLOCK = 0x5D52C70
LANDING_PAD = 0x5D52CDC


def _load(memory, address):
    try:
        return memory[address]
    except KeyError:
        raise ValueError("dereference of an unmapped address %#x" % address)


def predicate_value(memory, element_pointer):
    """The pinned 0x5f03b40 computation for one element pointer."""
    target = _load(memory, element_pointer)
    field = _load(memory, target + PREDICATE_FIELD_OFFSET)
    flag = 1 if field == 0 else 0
    return ((target & 0xFFFFFFFF) & 0xFFFFFF00) | flag, target


def guarded_convert(owner, memory, events=None):
    """Run the pinned behaviour.

    owner: dict with "mutex_0x9c8" (opaque token), and the
    slot values "slot_0xb50", "slot_0xb58", "slot_0xb68"
    (integers standing for the qwords stored there).
    memory: dict mapping an integer address to the qword
    stored there; element and target slots are looked up here.
    events: optional list receiving ("acquire", mutex),
    ("convert", element_pointer, target) and ("release", mutex)
    in order, so tests can pin the call sequence.

    Returns the 32-bit value described above.
    """
    if owner is None:
        raise ValueError("null owner pointer")
    mutex = owner["mutex_0x9c8"]
    if events is not None:
        events.append(("acquire", mutex))
    first = owner["slot_0xb50"]
    second = owner["slot_0xb58"]
    if first != second:
        element_pointer = _load(memory, first - 0x18)
    else:
        end_slot = _load(memory, owner["slot_0xb68"] - 8)
        element_pointer = _load(memory, end_slot + 0x200 - 0x18)
    result, target = predicate_value(memory, element_pointer)
    if events is not None:
        events.append(("convert", element_pointer, target))
        events.append(("release", mutex))
    return result
