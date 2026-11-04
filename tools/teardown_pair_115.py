"""Python model of node #115's storage-release leaf at 0x5f78000 and
container-clear leaf at 0x5f78030.

RE-001 work item: research/work-items/RE-001-teardown-pair-115/.
The release leaf takes an object in rdi, reads the qword at obj+0x00
(begin) and the qword at obj+0x10 (capacity end), and, when begin is
nonzero, tail-jumps to operator delete with (begin, capacity - begin)
wrapping mod 2**64; a zero begin returns at once with no delete. The
leaf itself writes nothing: the object's fields are left exactly as
they were. The clear leaf takes an object in rdi, stores zero at
obj+0x00 when that qword is nonzero, then reads the qwords at
obj+0x190 (begin) and obj+0x198 (end) and, when they differ, stores
begin at obj+0x198, so the sub-container at +0x190 is emptied while
its capacity qword at +0x1a0 is never touched. Neither leaf makes
any other call, and neither leaf's meaning for the fields beyond
the offsets read and written is claimed.
"""

MASK64 = (1 << 64) - 1


def release_storage(obj):
    """Apply the 0x5f78000 rule.

    Returns (begin, size) for the sized delete the leaf tail-jumps
    to, or None when begin is zero and the leaf returns at once.
    Raises ValueError when a field the leaf reads is absent, so a
    caller cannot silently model a partially known object. The
    object mapping itself is never mutated: the leaf writes nothing.
    """
    if 0x00 not in obj or 0x10 not in obj:
        raise ValueError("obj is missing field 0x00 or 0x10")
    begin = obj[0x00]
    if begin == 0:
        return None
    return (begin, (obj[0x10] - begin) & MASK64)


def clear_container(obj):
    """Apply the 0x5f78030 rule in place.

    Raises ValueError when a field the leaf reads or writes is
    absent. Returns the object mapping, for chaining.
    """
    if 0x00 not in obj or 0x190 not in obj or 0x198 not in obj:
        raise ValueError("obj is missing field 0x00, 0x190 or 0x198")
    if obj[0x00] != 0:
        obj[0x00] = 0
    if obj[0x190] != obj[0x198]:
        obj[0x198] = obj[0x190]
    return obj


def cleanup_sequence(first, middle, third, deletes):
    """Apply the 0x5f7f280 cleanup order: release the first object,
    clear the middle object, then release the third object, in that
    order, appending each sized delete to ``deletes``.

    This models only the three leaf calls and their order in that
    function; the function's wider behavior is not claimed.
    """
    result = release_storage(first)
    if result is not None:
        deletes.append(result)
    clear_container(middle)
    result = release_storage(third)
    if result is not None:
        deletes.append(result)


def landing_sequence(shared, cleared, slot8_zero, deletes):
    """Apply the 0x5f7ede0 landing-pad order: release the shared
    object, then, only when ``slot8_zero`` (the qword at the
    caller's stack slot 0x8(%rsp) is zero), clear the second object
    and release the shared object a second time, appending each
    sized delete to ``deletes``.

    The surrounding exception-handling calls (__cxa_begin_catch,
    __cxa_rethrow) and the nonzero-slot arm are not modelled; only
    the leaf calls and their order are.
    """
    result = release_storage(shared)
    if result is not None:
        deletes.append(result)
    if slot8_zero:
        clear_container(cleared)
        result = release_storage(shared)
        if result is not None:
            deletes.append(result)
