"""Model of node #115 routine 0x5d5ae50: destructor of a vector of
0x70-byte records, each holding three string-vectors.

Holder layout (vector triple): begin at +0x00, end at +0x08,
capacity end at +0x10. The outer loop walks records from begin
to end in steps of 0x70; a begin equal to end skips the loop.

Each record holds three string-vectors, torn down in this fixed
order: the vector at +0x50 (begin +0x50, end +0x58, capacity end
+0x60), then the vector at +0x38 (begin +0x38, end +0x40,
capacity end +0x48), then the vector at +0x08 (begin +0x08,
end +0x10, capacity end +0x18). Each vector walk visits 0x20-byte
elements in order; a string element is disposed under the
short-form rule the routine pins: when the element data pointer
equals the element's own +0x10 slot address, the string is in
short form and nothing is freed; otherwise the sized delete
frees capacity + 1 bytes. After a vector's elements, the
vector's own buffer is freed as one span (capacity end minus
begin) whenever the begin pointer is non-null; a null begin
frees nothing for that vector. Record fields outside the three
vectors (+0x00..+0x08, +0x20..+0x38, +0x68..+0x70) are never
read by the routine and are not modelled.

Exit: the holder's own buffer is freed as one span (holder
capacity end minus holder begin) whenever the holder begin is
non-null, even for an empty vector; a null holder begin returns
plainly. The holder itself is never freed.

Representation: a string element is (short_form, capacity);
a vector is a dict with "elems" (list of elements in walk
order), "begin" (int address or None) and "cap" (int address
or None); a record is a dict with keys "v50", "v38", "v08";
a holder is a dict with "records" (list, in walk order),
"begin" and "cap". ``destroy`` returns the ordered event list:
("free", size) for a heap string, ("free_span", size) for a
vector or holder buffer span. An inconsistent shape (a null
begin paired with elements, or a null holder begin paired with
records) raises ValueError, mirroring that the routine would
walk a range it cannot bound.
"""


def _dispose_string(elem, events):
    short_form, capacity = elem
    if not short_form:
        events.append(("free", capacity + 1))


def _teardown_string_vector(vec, events):
    if vec["begin"] is None:
        if vec["elems"]:
            raise ValueError("null vector begin with elements")
        return
    for elem in vec["elems"]:
        _dispose_string(elem, events)
    events.append(("free_span", vec["cap"] - vec["begin"]))


def _teardown_record(rec, events):
    for key in ("v50", "v38", "v08"):
        _teardown_string_vector(rec[key], events)


def destroy(holder, events=None):
    """Return the ordered free events for destroying ``holder``."""
    if events is None:
        events = []
    if holder["begin"] is None:
        if holder["records"]:
            raise ValueError("null holder begin with records")
    else:
        for rec in holder["records"]:
            _teardown_record(rec, events)
    if holder["begin"] is not None:
        events.append(("free_span", holder["cap"] - holder["begin"]))
    return events
