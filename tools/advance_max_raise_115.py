"""Python model of node #115's twin field-raise leaves at 0x5f6f400
(advance-past) and 0x5f6f430 (max-store).

RE-001 work item: research/work-items/RE-001-advance-max-field-raise-115/.
Both leaves take (obj, value) in (rdi, rsi) and return void. All
comparisons are unsigned 64-bit; all arithmetic wraps mod 2**64.
The advance leaf stores value + 1 at obj+0xd8 exactly when
value >= the current qword there, else stores nothing. The max leaf
stores value at obj+0xe0 exactly when the current qword there is
below value, else stores nothing. Neither leaf touches the other's
field, makes calls, or reads anything else.
"""

MASK64 = (1 << 64) - 1


def advance_past(obj, value):
    """Apply the 0x5f6f400 rule to a mapping keyed by field offset.

    Raises ValueError when field 0xd8 is absent, so a caller cannot
    silently model a partially known object.
    """
    if 0xD8 not in obj:
        raise ValueError("obj is missing field 0xd8")
    if value >= obj[0xD8]:
        obj[0xD8] = (value + 1) & MASK64


def max_store(obj, value):
    """Apply the 0x5f6f430 rule to a mapping keyed by field offset.

    Raises ValueError when field 0xe0 is absent, so a caller cannot
    silently model a partially known object.
    """
    if 0xE0 not in obj:
        raise ValueError("obj is missing field 0xe0")
    if obj[0xE0] < value:
        obj[0xE0] = value


def shared_caller_sequence(obj, value_max, value_adv1, value_adv2):
    """Apply the shared caller (0x5f9daf0) triple in order: max-store
    with value_max, then advance-past with value_adv1, then
    advance-past with value_adv2, all on the same object.
    """
    max_store(obj, value_max)
    advance_past(obj, value_adv1)
    advance_past(obj, value_adv2)
