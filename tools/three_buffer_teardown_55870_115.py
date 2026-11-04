"""Python model of node #115 routine 0x5d55870: three-buffer teardown.

The routine takes one object pointer, returns nothing, and frees four
fields in a fixed order. It writes nothing back to the object. The
model records the observable frees in order; it does not model the
contents of the buffers or the internals of the release helper
0x5d350c0 (pinned by call shape only; its contract is established
in the RE-001 derived-destructor packet for the same address).

Buffer rule (all three buffers): a null begin pointer skips that
buffer only; otherwise the sized delete is (begin, end - begin),
including size 0 for an empty but non-null buffer.
"""


def teardown(buf_a, buf_b, buf_c, ref48):
    """Return the ordered list of observable frees.

    Each buf is (begin, end) with begin None for null. ref48 is None
    for null, otherwise an opaque identifier for the refcounted field.
    A free is ("sized_delete", buffer_name, begin, size) or
    ("release", ref48).
    """
    frees = []
    for name, buf in (("A", buf_a), ("B", buf_b), ("C", buf_c)):
        begin, end = buf
        if begin is not None:
            frees.append(("sized_delete", name, begin, end - begin))
    if ref48 is not None:
        frees.append(("release", ref48))
    return frees
