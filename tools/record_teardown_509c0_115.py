"""Model of node #115 routine 0x5d509c0: teardown of one record.

The routine takes one argument, the record pointer in rdi, and
reads exactly four things:

  +0x50  flag byte: nonzero destroys the +0xc0 member first
  +0x70  second heap buffer pointer (delete[] when non-null)
  +0x80  first heap buffer pointer (delete[] when non-null)
  +0xc0  condition variable, destroyed only when the flag is nonzero

Sequence, in order: condition-variable destroy (flag-gated),
delete[] of the +0x80 pointer (null skipped), delete[] of the
+0x70 pointer (null skipped, via a tail jump to the same delete[]
entry point, so the observable effect is identical). The routine
does NOT free the record itself and writes no record slot.

The model is event-based: a record is a Record object holding the
flag byte and two buffer tokens (a token string, or None for a
null pointer). teardown_record returns the ordered event list:
("condition_variable", "destroy") and/or ("delete_array", offset,
token). It raises on a flag byte outside 0..255 or on a non-string
buffer token, as model safety properties, not binary claims (the
binary's behaviour on dangling pointers is not claimed).
"""

FLAG_OFFSET = 0x50
SECOND_BUFFER_OFFSET = 0x70
FIRST_BUFFER_OFFSET = 0x80
CONDITION_VARIABLE_OFFSET = 0xC0


class Record:
    """One record as the routine sees it. ``name`` is a test label."""

    def __init__(self, name, flag=0, buffer_80=None, buffer_70=None):
        if not isinstance(flag, int) or not 0 <= flag <= 255:
            raise ValueError("flag must be a byte value 0..255")
        for token in (buffer_80, buffer_70):
            if token is not None and not isinstance(token, str):
                raise TypeError("buffer token must be a string or None")
        self.name = name
        self.flag = flag
        self.buffer_80 = buffer_80
        self.buffer_70 = buffer_70


def teardown_record(record):
    """Return the ordered teardown events for ``record``.

    The record object is left unchanged: the routine writes no
    record slot and never frees the record itself.
    """
    if not isinstance(record, Record):
        raise TypeError("record must be a Record (the binary reads"
                        " +0x50 immediately, so a null record is not"
                        " a defined input)")
    events = []
    if record.flag != 0:
        events.append(("condition_variable", "destroy"))
    if record.buffer_80 is not None:
        events.append(("delete_array", FIRST_BUFFER_OFFSET,
                       record.buffer_80))
    if record.buffer_70 is not None:
        events.append(("delete_array", SECOND_BUFFER_OFFSET,
                       record.buffer_70))
    return events
