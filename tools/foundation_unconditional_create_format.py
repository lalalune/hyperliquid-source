"""Model of node #94 function 0x514e9f0: unconditional create-and-format.

The binary function takes an outer object and a destination string. It
runs the get-or-create lookup 0x51e9220 unconditionally -- there is no
view argument and no parser or index gate, unlike its sibling 0x514eb90.
The lookup is called with a status slot, the field at
[[outer + 0x788] + 0x30] and a shared slot (zeroed before the call).

- Status byte nonzero (entry already existed): run the cleanup (status
  array pointer via _ZdaPv when nonzero, shared control pointer via
  0x4f94a90 when nonzero) and return 0 with the destination unchanged.
- Status byte zero (fresh record created): build '=' and '; ' as inline
  stack strings (no string-constructor call), format the fresh record
  pointer with 0x5407f00 into a temporary string, move-assign the
  temporary into the destination with 0x514b4f0, dispose the temporary
  and the two separator strings in that order, run the cleanup, and
  return 1.

The model takes the lookup and formatter as callables so tests can drive
both dispatch arms end to end without executing the target binary. The
formatter's output text for a given record is a callee-only unknown; the
model passes the record pointer through and formats whatever the
injected formatter returns, exactly as the binary passes its record
pointer to the formatter without interpreting it.
"""

EQUALS = "="
SEPARATOR = "; "

# Disposal / release event names, in the order the binary performs them
# on the format path: temporary, separator, equals, then the cleanup
# (status array, then shared control).
DISPOSE_TEMP = "dispose:temp"
DISPOSE_SEPARATOR = "dispose:separator"
DISPOSE_EQUALS = "dispose:equals"
RELEASE_ARRAY = "release:status-array"
RELEASE_CONTROL = "release:shared-control"


class LookupOutcome:
    """What the get-or-create lookup leaves in the caller's slots."""

    def __init__(self, status_byte, status_array=None, record=None,
                 control=None):
        # status_byte: the first byte of the status struct. Nonzero means
        # the entry already existed; zero means a fresh record was created
        # and stored in the shared slot.
        self.status_byte = status_byte
        # status_array: the status struct's +0x18 array pointer (None
        # means zero, so the cleanup skips it).
        self.status_array = status_array
        # record / control: the shared slot's pair on the create path
        # (None on the found path, where the lookup leaves the slot
        # untouched -- here zeroed before the call).
        self.record = record
        self.control = control


def build_separators():
    """The two inline stack strings, exactly as the binary builds them.

    '=' is one byte 0x3d with length 1; '; ' is bytes 0x3b 0x20 with
    length 2 and a NUL terminator. No string-constructor call is involved,
    unlike the indexed sibling 0x514eb90.
    """
    return EQUALS, SEPARATOR


def unconditional_create_format(lookup_fn, format_fn, events):
    """Run the modelled function.

    lookup_fn: zero-argument callable returning a LookupOutcome.
    format_fn: callable (record, separator, equals) -> str, standing in
        for the record formatter 0x5407f00.
    events: a list the model appends disposal/release events to, in
        binary order, so tests can pin the cleanup sequence.

    Returns (return_code, destination_or_None): return_code 1 with the
    formatted text on the create path, 0 with None (destination
    unchanged) on the found path.
    """
    outcome = lookup_fn()
    if outcome.status_byte != 0:
        # Found path: cleanup only, destination untouched.
        if outcome.status_array is not None:
            events.append(RELEASE_ARRAY)
        if outcome.control is not None:
            events.append(RELEASE_CONTROL)
        return 0, None
    equals, separator = build_separators()
    text = format_fn(outcome.record, separator, equals)
    # Move-assign the temporary into the destination, then dispose the
    # temporary and the two separator strings in that order.
    events.append(DISPOSE_TEMP)
    events.append(DISPOSE_SEPARATOR)
    events.append(DISPOSE_EQUALS)
    # Cleanup: status array first, then shared control.
    if outcome.status_array is not None:
        events.append(RELEASE_ARRAY)
    if outcome.control is not None:
        events.append(RELEASE_CONTROL)
    return 1, text
