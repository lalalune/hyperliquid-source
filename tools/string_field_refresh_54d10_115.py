"""Model of node #115 routine 0x5d54d10: refresh a holder's string
field from the registry accessor's output.

A string value is a dict:
  {"data": bytes | None, "heap": bool, "capacity": int | None}
where "data" is the string bytes (None means a null pointer, only
valid for a heap value), "heap" selects the heap form (buffer owned
elsewhere, capacity meaningful) versus the short form (buffer inline,
at most 15 bytes), and "capacity" is the heap capacity (None for
short form).

assign_produced(dest, produced) reproduces the routine's assignment
tail after the accessor call (records.json, "assignment_rules"):
  - heap produced: move. The destination takes the produced pointer,
    size and capacity; the produced temp is reset to empty short
    form and frees nothing.
  - short produced: copy. The produced bytes are copied into the
    destination's existing buffer; the destination keeps its pointer
    and capacity; the produced temp frees nothing (short form).
  - on the move path only, a previous heap destination buffer with a
    non-null pointer is freed with (old capacity + 1).
Returns (new_dest, frees) where frees is a list of ("old", size)
entries, size being the sized-delete size argument.
refresh_string_field(dest, accessor_output) is the whole routine:
the accessor call (output as input) followed by the assignment.
"""

MAX_SHORT = 15


def _check(value, name):
    data, heap, capacity = value["data"], value["heap"], value["capacity"]
    if heap:
        assert capacity is not None, f"{name}: heap value needs capacity"
        if data is not None:
            assert len(data) <= capacity, f"{name}: size over capacity"
    else:
        assert capacity is None, f"{name}: short value needs no capacity"
        assert data is not None, f"{name}: short value needs a buffer"
        assert len(data) <= MAX_SHORT, f"{name}: short value over 15 bytes"


def assign_produced(dest, produced):
    _check(dest, "dest")
    _check(produced, "produced")
    frees = []
    if produced["heap"]:
        # Move path (routine: destination short-form + heap produced,
        # or destination heap + heap produced).
        if dest["heap"] and dest["data"] is not None:
            frees.append(("old", dest["capacity"] + 1))
        new_dest = {"data": produced["data"], "heap": True,
                    "capacity": produced["capacity"]}
    else:
        # Copy path (routine: either destination form + short
        # produced). The destination buffer must exist: a null-pointer
        # destination cannot receive a copy, matching the binary,
        # which stores through the destination pointer unconditionally.
        assert dest["data"] is not None, "copy into null-pointer dest"
        if dest["heap"]:
            assert dest["capacity"] >= len(produced["data"]), \
                "copy overflows heap destination"
        new_dest = {"data": produced["data"], "heap": dest["heap"],
                    "capacity": dest["capacity"]}
    return new_dest, frees


def refresh_string_field(dest, accessor_output):
    """Whole routine: accessor output (input) assigned into dest."""
    return assign_produced(dest, accessor_output)
